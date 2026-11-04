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

/** The five commands that arm a UID write, in order, from the vendor app's `SetUID` path
 * (`com.fnstar.sniffercard.NFCReadActivity`).
 *
 * They are READ commands by opcode, and the pages they name mean nothing as pages - the sequence
 * itself is the knock. Proxmark3 has no equivalent: `hf mf supercard` answers "Not supported on
 * this card" for Gen2, so this is the one thing the vendor app knows that it does not.
 */
static const uint8_t sniffer_card_uid_knock[] = {0xF3, 0x2A, 0xBD, 0xEF, 0x01};

/** UID bytes the vendor app sends, whatever the card's own UID length.
 *
 * It always sends seven, zero-padding a 4-byte UID, which makes the last three commands `30 00` -
 * a read of page 0 by opcode.
 */
#define SNIFFER_CARD_UID_WRITE_BYTES 7

/** Ways of performing the knock, tried in turn until the card answers as its new self.
 *
 * The sequence itself is not in doubt - it came out of the vendor app, and Proxmark3 confirms the
 * card is a Super Gen2, for which it has no UID write of its own to compare against. What is in
 * doubt is how it has to be delivered. Android spends milliseconds of JVM overhead between
 * transceive calls; the Flipper sends frames as fast as the field allows, which a card writing
 * EEPROM between bytes could be overrun by. And the seven-byte padding on a 4-byte card is the
 * vendor app's choice, not a documented requirement.
 *
 * Trying them in one session rather than one per build is what makes each tap of the card worth
 * something: the log names the variant that took.
 */
typedef struct {
    const char* name;
    /** Bytes of UID to send; 0 means send exactly the card's own UID length. */
    uint8_t uid_bytes;
    /** Pause after each command, in milliseconds. */
    uint32_t gap_ms;
} SnifferCardWriteVariant;

static const SnifferCardWriteVariant sniffer_card_write_variants[] = {
    {"7 bytes, no gap", SNIFFER_CARD_UID_WRITE_BYTES, 0},
    {"7 bytes, 20ms gap", SNIFFER_CARD_UID_WRITE_BYTES, 20},
    {"UID length, 20ms gap", 0, 20},
};

#define SNIFFER_CARD_POLLER_MAX_BUFFER_SIZE (64U)
#define SNIFFER_CARD_POLLER_MAX_FWT         (150000U)

/** SAK of a tag with no MIFARE Classic personality at all.
 *
 * A plain Ultralight or NTAG answers `30 00` with sixteen bytes exactly as these cards do, so the
 * read alone cannot tell them apart. Nothing that sniffs Classic authentications presents this
 * SAK, so it is the cheap half of the check and it runs first.
 */
#define SNIFFER_CARD_SAK_NOT_CLASSIC (0x00)

/** Where a UID-write session has got to.
 *
 * The write and the read-back are two activations of the same card: a card that has just been
 * given a new UID is still selected under the old one, so it has to be selected again before it
 * will say what it has become.
 *
 * Getting there is a field cycle, not a HLTA. Halting the card would leave it answering only
 * WUPA, and the firmware activates with REQA alone
 * (`iso14443_3a_poller_activate()` -> `NfcIso14443aShortFrameSensReq`), so a halted card would
 * never come back and every write would read as unconfirmed. Returning NfcCommandReset instead
 * takes the field down for 100 ms and brings it up
 * (`nfc_worker_poller_reset_handler()` in `lib/nfc/nfc.c`), which powers the card out of any
 * state it was left in.
 */
typedef enum {
    SnifferCardWriteStepWrite,
    SnifferCardWriteStepVerify,
} SnifferCardWriteStep;

struct SnifferCardPoller {
    Nfc* nfc;
    /** Allocated per session and freed with it, because an NfcPoller is single-use.
     *
     * `nfc_poller_alloc()` is what calls `nfc_config()` on the way down
     * (`iso14443_3a_poller_alloc()` in `lib/nfc/protocols/iso14443_3a/iso14443_3a_poller.c`), and
     * a session that ends puts the configuration state back to Idle
     * (`nfc_worker_poller_stop_handler()`). `nfc_start()` hard-checks that state, so starting a
     * second session on one poller is a furi_check failure, not a quiet misbehaviour - it takes
     * the whole app down.
     *
     * NULL between sessions, which is also what makes stopping twice harmless: every scene stops
     * in its on_exit whether or not its session is still running.
     */
    NfcPoller* poller;
    BitBuffer* tx_buffer;
    BitBuffer* rx_buffer;

    SnifferCardPollerMode mode;
    SnifferCardPollerCallback callback;
    void* context;

    uint8_t uid_to_write[SNIFFER_CARD_UID_WRITE_BYTES];
    size_t uid_to_write_len;
    SnifferCardWriteStep write_step;
    /** Which of sniffer_card_write_variants is being tried. */
    size_t write_variant;

    SnifferCardPollerResult result;
    SnifferCardIdentity identity;
    SnifferTrace traces[SNIFFER_CARD_TRACE_SLOTS];
    size_t trace_count;
    size_t slots_read;
};

MfClassicType sniffer_card_identity_get_type(const SnifferCardIdentity* identity) {
    furi_assert(identity);

    if(identity->sak == 0x09) return MfClassicTypeMini; // shares the 1K bit, so test it first
    if(identity->sak & 0x10) return MfClassicType4k; // 0x18, and 0x38 for SmartMX with Classic
    if(identity->sak & 0x08) return MfClassicType1k; // 0x08, and 0x28 for SmartMX with Classic

    return MfClassicTypeNum;
}

const char* sniffer_card_identity_get_type_name(const SnifferCardIdentity* identity) {
    switch(sniffer_card_identity_get_type(identity)) {
    case MfClassicTypeMini:
        return "Mini";
    case MfClassicType1k:
        return "1K";
    case MfClassicType2k:
        return "2K";
    case MfClassicType4k:
        return "4K";
    default:
        return "not Classic";
    }
}

SnifferCardPoller* sniffer_card_poller_alloc(Nfc* nfc) {
    furi_assert(nfc);

    SnifferCardPoller* instance = malloc(sizeof(SnifferCardPoller));
    instance->nfc = nfc;
    instance->poller = NULL;
    instance->tx_buffer = bit_buffer_alloc(SNIFFER_CARD_POLLER_MAX_BUFFER_SIZE);
    instance->rx_buffer = bit_buffer_alloc(SNIFFER_CARD_POLLER_MAX_BUFFER_SIZE);
    instance->mode = SnifferCardPollerModeReadIdentity;
    instance->callback = NULL;
    instance->context = NULL;
    instance->uid_to_write_len = 0;
    instance->write_step = SnifferCardWriteStepWrite;
    instance->write_variant = 0;
    instance->result = SnifferCardPollerResultWaiting;
    memset(&instance->identity, 0, sizeof(instance->identity));
    instance->trace_count = 0;
    instance->slots_read = 0;

    return instance;
}

void sniffer_card_poller_free(SnifferCardPoller* instance) {
    furi_assert(instance);

    // Normally already stopped by the scene's on_exit, which Back always runs. Guarded rather
    // than trusted, because leaving a session running past its owner is how the radio stays on.
    sniffer_card_poller_stop(instance);
    bit_buffer_free(instance->tx_buffer);
    bit_buffer_free(instance->rx_buffer);
    free(instance);
}

void sniffer_card_poller_set_uid(SnifferCardPoller* instance, const uint8_t* uid, size_t uid_len) {
    furi_assert(instance);
    furi_assert(uid);
    furi_check(uid_len <= sizeof(instance->uid_to_write));

    // Zero-padded to the full seven the knock sends, so the write path never reads past what was
    // given to it.
    memset(instance->uid_to_write, 0, sizeof(instance->uid_to_write));
    memcpy(instance->uid_to_write, uid, uid_len);
    instance->uid_to_write_len = uid_len;
}

/** Hex for the log, where what a card actually answered is the whole question. */
static void sniffer_card_log_bytes(const char* label, const uint8_t* data, size_t len) {
    FuriString* hex = furi_string_alloc();
    for(size_t i = 0; i < len; i++) {
        furi_string_cat_printf(hex, "%02X", data[i]);
    }
    FURI_LOG_D(TAG, "%s %s", label, furi_string_get_cstr(hex));
    furi_string_free(hex);
}

/** Send one `30 <arg>` and keep the answer.
 *
 * Logged command and answer both: these cards are documented by two sources that disagree, and
 * the only way to tell which sequence a particular one speaks is to see what it says back.
 */
static bool sniffer_card_poller_read_cmd(
    SnifferCardPoller* instance,
    Iso14443_3aPoller* iso3_poller,
    uint8_t arg) {
    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_byte(instance->tx_buffer, SNIFFER_CARD_CMD_READ);
    bit_buffer_append_byte(instance->tx_buffer, arg);

    const Iso14443_3aError error = iso14443_3a_poller_send_standard_frame(
        iso3_poller, instance->tx_buffer, instance->rx_buffer, SNIFFER_CARD_POLLER_MAX_FWT);

    if(error != Iso14443_3aErrorNone) {
        FURI_LOG_D(TAG, "30 %02X -> error %d", arg, error);
        return false;
    }

    FuriString* label = furi_string_alloc_printf("30 %02X ->", arg);
    sniffer_card_log_bytes(
        furi_string_get_cstr(label),
        bit_buffer_get_data(instance->rx_buffer),
        bit_buffer_get_size_bytes(instance->rx_buffer));
    furi_string_free(label);

    return true;
}

/** Take the UID and SAK off the activation the poller has just done. */
static void
    sniffer_card_poller_take_identity(SnifferCardPoller* instance, SnifferCardIdentity* identity) {
    const Iso14443_3aData* data = nfc_poller_get_data(instance->poller);

    size_t uid_len = 0;
    const uint8_t* uid = iso14443_3a_get_uid(data, &uid_len);

    furi_check(uid_len <= sizeof(identity->uid));
    memset(identity, 0, sizeof(*identity));
    memcpy(identity->uid, uid, uid_len);
    identity->uid_len = uid_len;
    identity->sak = iso14443_3a_get_sak(data);
}

/** Read every trace slot the card will give up.
 *
 * Only the commands the vendor's own app sends on its read path are used. Its UID-write path
 * opens with `30 F3`, whose answer is a better identity signature than anything here - but that
 * byte is also the first step of a five-command sequence that arms a UID write, and nothing
 * establishes what a card does with a lone, unfinished knock. A read must not be able to change
 * the card, so the signature is not worth it.
 */
static SnifferCardPollerResult
    sniffer_card_poller_read_traces(SnifferCardPoller* instance, Iso14443_3aPoller* iso3_poller) {
    if(instance->identity.sak == SNIFFER_CARD_SAK_NOT_CLASSIC) {
        FURI_LOG_I(TAG, "Not a Classic-emulating tag, SAK %02X", instance->identity.sak);
        return SnifferCardPollerResultWrongCard;
    }

    instance->trace_count = 0;
    instance->slots_read = 0;

    for(uint8_t page = 0; page < SNIFFER_CARD_TRACE_SLOTS; page++) {
        if(!sniffer_card_poller_read_cmd(instance, iso3_poller, page)) break;
        if(bit_buffer_get_size_bytes(instance->rx_buffer) != SNIFFER_CARD_TRACE_SIZE) break;

        uint8_t raw[SNIFFER_CARD_TRACE_SIZE];
        bit_buffer_write_bytes(instance->rx_buffer, raw, sizeof(raw));
        instance->slots_read++;

        SnifferTrace trace;
        if(sniffer_trace_parse_gen2(raw, &trace)) {
            instance->traces[instance->trace_count++] = trace;
        }
    }

    // A MIFARE Classic answers an unauthenticated read with a NAK, so no slot read at all is the
    // ordinary outcome for an ordinary card and not an error worth reporting as one.
    if(instance->slots_read == 0) {
        FURI_LOG_I(TAG, "No slot answered: not a Gen2 sniffer card");
        return SnifferCardPollerResultWrongCard;
    }

    FURI_LOG_I(TAG, "%zu slots read, %zu captures", instance->slots_read, instance->trace_count);

    return SnifferCardPollerResultSuccess;
}

/** Knock, then write the UID a byte per command. */
static SnifferCardPollerResult
    sniffer_card_poller_write_uid(SnifferCardPoller* instance, Iso14443_3aPoller* iso3_poller) {
    if(instance->identity.sak == SNIFFER_CARD_SAK_NOT_CLASSIC) {
        FURI_LOG_I(TAG, "Not a Classic-emulating tag, SAK %02X", instance->identity.sak);
        return SnifferCardPollerResultWrongCard;
    }

    // The vendor app refuses this too, and for a physical reason: the card is a 4-byte or a
    // 7-byte part. Writing a 7-byte UID into a 4-byte card has nowhere to put the other three
    // bytes, and the reader the card is meant to fool would see a UID of the wrong length.
    if(instance->identity.uid_len != instance->uid_to_write_len) {
        FURI_LOG_W(
            TAG,
            "Card UID is %zu bytes, asked to write %zu",
            instance->identity.uid_len,
            instance->uid_to_write_len);
        return SnifferCardPollerResultUidLenMismatch;
    }

    const SnifferCardWriteVariant* variant = &sniffer_card_write_variants[instance->write_variant];
    const size_t uid_bytes = variant->uid_bytes ? variant->uid_bytes : instance->uid_to_write_len;

    sniffer_card_log_bytes(
        "sniffer UID before:", instance->identity.uid, instance->identity.uid_len);
    sniffer_card_log_bytes("UID to write:", instance->uid_to_write, uid_bytes);
    FURI_LOG_I(TAG, "SAK %02X, variant: %s", instance->identity.sak, variant->name);

    for(size_t i = 0; i < COUNT_OF(sniffer_card_uid_knock); i++) {
        if(!sniffer_card_poller_read_cmd(instance, iso3_poller, sniffer_card_uid_knock[i])) {
            FURI_LOG_E(TAG, "Knock step %zu failed", i);
            return SnifferCardPollerResultError;
        }
        if(variant->gap_ms) furi_delay_ms(variant->gap_ms);
    }

    for(size_t i = 0; i < uid_bytes; i++) {
        if(!sniffer_card_poller_read_cmd(instance, iso3_poller, instance->uid_to_write[i])) {
            FURI_LOG_E(TAG, "UID byte %zu failed", i);
            return SnifferCardPollerResultError;
        }
        if(variant->gap_ms) furi_delay_ms(variant->gap_ms);
    }

    return SnifferCardPollerResultSuccess;
}

/** Compare what the card answers as now against what it was told to be. */
static SnifferCardPollerResult sniffer_card_poller_verify_uid(SnifferCardPoller* instance) {
    SnifferCardIdentity after;
    sniffer_card_poller_take_identity(instance, &after);
    instance->identity = after;

    sniffer_card_log_bytes("sniffer UID after:", after.uid, after.uid_len);

    if(after.uid_len != instance->uid_to_write_len ||
       memcmp(after.uid, instance->uid_to_write, after.uid_len) != 0) {
        FURI_LOG_E(
            TAG,
            "variant '%s' did not take",
            sniffer_card_write_variants[instance->write_variant].name);
        return SnifferCardPollerResultWriteMismatch;
    }

    FURI_LOG_I(
        TAG, "variant '%s' took", sniffer_card_write_variants[instance->write_variant].name);

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

    if(iso3_event->type != Iso14443_3aPollerEventTypeReady) {
        // The read-back is the one place where a tag failing to activate is a verdict rather
        // than something to keep waiting through: the card was there a moment ago, and if it is
        // not there now then nothing can confirm what the write did.
        if(instance->mode == SnifferCardPollerModeWriteUid &&
           instance->write_step == SnifferCardWriteStepVerify) {
            instance->result = SnifferCardPollerResultWriteUnverified;
            instance->callback(instance->context);
            return NfcCommandStop;
        }

        // Otherwise an empty field is the normal state of the screen that started this session,
        // which is asking for a card to be presented.
        return NfcCommandContinue;
    }

    if(instance->mode == SnifferCardPollerModeWriteUid &&
       instance->write_step == SnifferCardWriteStepVerify) {
        instance->result = sniffer_card_poller_verify_uid(instance);

        // A variant that did not take is not the end of the session while another is untried:
        // the card is still on the Flipper and has just been power-cycled, which is exactly the
        // state the next variant wants to start from.
        if(instance->result == SnifferCardPollerResultWriteMismatch &&
           instance->write_variant + 1 < COUNT_OF(sniffer_card_write_variants)) {
            instance->write_variant++;
            instance->write_step = SnifferCardWriteStepWrite;
            return NfcCommandReset;
        }

        instance->callback(instance->context);
        return NfcCommandStop;
    }

    sniffer_card_poller_take_identity(instance, &instance->identity);

    switch(instance->mode) {
    case SnifferCardPollerModeReadIdentity:
        instance->result = SnifferCardPollerResultSuccess;
        break;

    case SnifferCardPollerModeReadTraces:
        instance->result = sniffer_card_poller_read_traces(instance, iso3_poller);
        break;

    case SnifferCardPollerModeWriteUid:
        instance->result = sniffer_card_poller_write_uid(instance, iso3_poller);
        if(instance->result == SnifferCardPollerResultSuccess) {
            // Not a result yet: cycle the field so the card is powered down and selected again,
            // and judge the write on what it answers as then.
            instance->write_step = SnifferCardWriteStepVerify;
            return NfcCommandReset;
        }
        break;
    }

    instance->callback(instance->context);

    return NfcCommandStop;
}

void sniffer_card_poller_start(
    SnifferCardPoller* instance,
    SnifferCardPollerMode mode,
    SnifferCardPollerCallback callback,
    void* context) {
    furi_assert(instance);
    furi_assert(callback);

    instance->mode = mode;
    instance->callback = callback;
    instance->context = context;
    instance->write_step = SnifferCardWriteStepWrite;
    instance->write_variant = 0;
    instance->result = SnifferCardPollerResultWaiting;
    memset(&instance->identity, 0, sizeof(instance->identity));
    instance->trace_count = 0;
    instance->slots_read = 0;

    // A fresh poller for a fresh session; see SnifferCardPoller::poller for why it cannot be
    // allocated once and kept.
    furi_check(instance->poller == NULL);
    instance->poller = nfc_poller_alloc(instance->nfc, NfcProtocolIso14443_3a);

    nfc_poller_start(instance->poller, sniffer_card_poller_nfc_callback, instance);
}

void sniffer_card_poller_stop(SnifferCardPoller* instance) {
    furi_assert(instance);

    if(instance->poller == NULL) return;

    // Stopping is needed even when the session ended itself: the callback returning
    // NfcCommandStop ends the worker loop, but only nfc_stop() joins its thread and takes the
    // Nfc instance out of its running state.
    nfc_poller_stop(instance->poller);
    nfc_poller_free(instance->poller);
    instance->poller = NULL;
}

SnifferCardPollerResult sniffer_card_poller_get_result(const SnifferCardPoller* instance) {
    furi_assert(instance);

    return instance->result;
}

const SnifferCardIdentity* sniffer_card_poller_get_identity(const SnifferCardPoller* instance) {
    furi_assert(instance);

    return &instance->identity;
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
