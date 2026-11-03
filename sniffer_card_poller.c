#include "sniffer_card_poller.h"

#include <nfc/protocols/iso14443_3a/iso14443_3a_poller.h>

#define TAG "SnifferCard"

/** Ultralight-style READ, which is how a Gen2 card hands over its trace slots.
 *
 * The card emulates MIFARE Classic to the reader it is sniffing, but answers the Flipper on a
 * second, undocumented personality: a plain `30 <page>` with no authentication, which a genuine
 * Classic refuses outright. That refusal is what identifies the card.
 */
#define SNIFFER_CARD_CMD_READ (0x30)

#define SNIFFER_CARD_POLLER_MAX_BUFFER_SIZE (64U)
#define SNIFFER_CARD_POLLER_MAX_FWT         (150000U)

/** SAK of a tag with no MIFARE Classic personality at all.
 *
 * A plain Ultralight or NTAG answers `30 00` with sixteen bytes exactly as these cards do, so the
 * read alone cannot tell them apart. Nothing that sniffs Classic authentications presents this
 * SAK, so it is the cheap half of the check and it runs first.
 */
#define SNIFFER_CARD_SAK_NOT_CLASSIC (0x00)

struct SnifferCardPoller {
    NfcPoller* poller;
    BitBuffer* tx_buffer;
    BitBuffer* rx_buffer;

    SnifferCardPollerCallback callback;
    void* context;

    SnifferCardPollerResult result;
    SnifferTrace traces[SNIFFER_CARD_TRACE_SLOTS];
    size_t trace_count;
    size_t slots_read;
};

SnifferCardPoller* sniffer_card_poller_alloc(Nfc* nfc) {
    furi_assert(nfc);

    SnifferCardPoller* instance = malloc(sizeof(SnifferCardPoller));
    instance->poller = nfc_poller_alloc(nfc, NfcProtocolIso14443_3a);
    instance->tx_buffer = bit_buffer_alloc(SNIFFER_CARD_POLLER_MAX_BUFFER_SIZE);
    instance->rx_buffer = bit_buffer_alloc(SNIFFER_CARD_POLLER_MAX_BUFFER_SIZE);
    instance->callback = NULL;
    instance->context = NULL;
    instance->result = SnifferCardPollerResultWaiting;
    instance->trace_count = 0;
    instance->slots_read = 0;

    return instance;
}

void sniffer_card_poller_free(SnifferCardPoller* instance) {
    furi_assert(instance);

    nfc_poller_free(instance->poller);
    bit_buffer_free(instance->tx_buffer);
    bit_buffer_free(instance->rx_buffer);
    free(instance);
}

/** Read one slot into @p raw.
 *
 * A short or absent answer is how the last slot of a card with fewer slots than
 * SNIFFER_CARD_TRACE_SLOTS announces itself, so the caller treats it as the end of the card
 * rather than as a failure.
 */
static bool sniffer_card_poller_read_slot(
    SnifferCardPoller* instance,
    Iso14443_3aPoller* iso3_poller,
    uint8_t page,
    uint8_t* raw) {
    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_byte(instance->tx_buffer, SNIFFER_CARD_CMD_READ);
    bit_buffer_append_byte(instance->tx_buffer, page);

    const Iso14443_3aError error = iso14443_3a_poller_send_standard_frame(
        iso3_poller, instance->tx_buffer, instance->rx_buffer, SNIFFER_CARD_POLLER_MAX_FWT);
    if(error != Iso14443_3aErrorNone) return false;

    if(bit_buffer_get_size_bytes(instance->rx_buffer) != SNIFFER_CARD_TRACE_SIZE) return false;

    bit_buffer_write_bytes(instance->rx_buffer, raw, SNIFFER_CARD_TRACE_SIZE);

    return true;
}

/** Work through the activated tag: decide whether it is one of these cards, and if so read it.
 *
 * Only the commands the vendor's own app sends on its read path are used. Its UID-write path
 * opens with `30 F3`, whose answer is a better identity signature than anything here - but that
 * byte is also the first step of a five-command sequence that arms a UID write, and nothing
 * establishes what a card does with a lone, unfinished knock. A read must not be able to change
 * the card, so the signature is not worth it.
 */
static SnifferCardPollerResult
    sniffer_card_poller_read(SnifferCardPoller* instance, Iso14443_3aPoller* iso3_poller) {
    const Iso14443_3aData* data = nfc_poller_get_data(instance->poller);
    if(iso14443_3a_get_sak(data) == SNIFFER_CARD_SAK_NOT_CLASSIC) {
        FURI_LOG_D(TAG, "Not a Classic-emulating tag");
        return SnifferCardPollerResultNotSniffer;
    }

    instance->trace_count = 0;
    instance->slots_read = 0;

    for(uint8_t page = 0; page < SNIFFER_CARD_TRACE_SLOTS; page++) {
        uint8_t raw[SNIFFER_CARD_TRACE_SIZE];
        if(!sniffer_card_poller_read_slot(instance, iso3_poller, page, raw)) break;

        instance->slots_read++;

        SnifferTrace trace;
        if(sniffer_trace_parse_gen2(raw, &trace)) {
            instance->traces[instance->trace_count++] = trace;
        }
    }

    // A MIFARE Classic answers an unauthenticated read with a NAK, so no slot read at all is the
    // ordinary outcome for an ordinary card and not an error worth reporting as one.
    if(instance->slots_read == 0) {
        FURI_LOG_D(TAG, "No slot answered");
        return SnifferCardPollerResultNotSniffer;
    }

    FURI_LOG_I(TAG, "%zu slots read, %zu captures", instance->slots_read, instance->trace_count);

    return SnifferCardPollerResultSuccess;
}

static NfcCommand sniffer_card_poller_nfc_callback(NfcGenericEvent event, void* context) {
    furi_assert(context);
    furi_assert(event.protocol == NfcProtocolIso14443_3a);
    furi_assert(event.event_data);
    furi_assert(event.instance);

    SnifferCardPoller* instance = context;
    Iso14443_3aPoller* iso3_poller = event.instance;
    const Iso14443_3aPollerEvent* iso3_event = event.event_data;

    // Anything other than a tag standing activated in the field means keep waiting: the scene
    // that started this session is showing "place the card", and an empty field is that screen's
    // normal state rather than something to report.
    if(iso3_event->type != Iso14443_3aPollerEventTypeReady) return NfcCommandContinue;

    instance->result = sniffer_card_poller_read(instance, iso3_poller);
    instance->callback(instance->context);

    return NfcCommandStop;
}

void sniffer_card_poller_start(
    SnifferCardPoller* instance,
    SnifferCardPollerCallback callback,
    void* context) {
    furi_assert(instance);
    furi_assert(callback);

    instance->callback = callback;
    instance->context = context;
    instance->result = SnifferCardPollerResultWaiting;
    instance->trace_count = 0;
    instance->slots_read = 0;

    nfc_poller_start(instance->poller, sniffer_card_poller_nfc_callback, instance);
}

void sniffer_card_poller_stop(SnifferCardPoller* instance) {
    furi_assert(instance);

    nfc_poller_stop(instance->poller);
}

SnifferCardPollerResult sniffer_card_poller_get_result(const SnifferCardPoller* instance) {
    furi_assert(instance);

    return instance->result;
}

size_t
    sniffer_card_poller_get_traces(const SnifferCardPoller* instance, const SnifferTrace** traces) {
    furi_assert(instance);
    furi_assert(traces);

    *traces = instance->traces;

    return instance->trace_count;
}

size_t sniffer_card_poller_get_slots_read(const SnifferCardPoller* instance) {
    furi_assert(instance);

    return instance->slots_read;
}
