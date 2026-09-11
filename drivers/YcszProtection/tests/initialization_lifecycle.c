#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum init_state {
    INIT_IDLE = 0,
    INIT_INITIALIZING = 1,
    INIT_ACTIVE = 2
};

struct init_model {
    enum init_state state;
    uint64_t owner;
    uint64_t expires_at;
    uint32_t marked;
    uint32_t failures;
};

static void reset(struct init_model *model) {
    memset(model, 0, sizeof(*model));
}

static bool valid_init(const struct init_model *model, uint64_t owner, uint64_t now) {
    return model->state == INIT_INITIALIZING && model->owner == owner && now < model->expires_at;
}

static bool begin(struct init_model *model, uint64_t owner, uint64_t now) {
    if (model->state == INIT_ACTIVE) return false;
    if (model->state == INIT_INITIALIZING && now < model->expires_at) return false;
    model->state = INIT_INITIALIZING;
    model->owner = owner;
    model->expires_at = now + 120;
    model->marked = 0;
    model->failures = 0;
    return true;
}

static void record_stream(struct init_model *model, uint64_t owner, uint64_t now, bool marked) {
    if (!valid_init(model, owner, now)) return;
    if (marked) ++model->marked;
    else ++model->failures;
}

static bool commit(struct init_model *model, uint64_t owner, uint64_t now, uint32_t expected) {
    if (!valid_init(model, owner, now) || expected == 0 || model->failures != 0 || model->marked < expected) return false;
    model->state = INIT_ACTIVE;
    model->expires_at = 0;
    return true;
}

static bool abort_init(struct init_model *model, uint64_t owner) {
    if (model->state != INIT_INITIALIZING || model->owner != owner) return false;
    reset(model);
    return true;
}

static bool namespace_mutation_allowed(const struct init_model *model, const char *path, bool mutation) {
    const char *product = "\\\\Device\\\\Volume\\\\Ycsz";
    size_t length = strlen(product);
    bool in_product = strncmp(path, product, length) == 0 && (path[length] == '\0' || path[length] == '\\');
    if (model->state != INIT_INITIALIZING || !mutation) return true;
    return !in_product;
}

int main(void) {
    struct init_model model;
    reset(&model);

    // The scan cannot publish Active merely because Begin succeeded.
    assert(begin(&model, 10, 100));
    assert(model.state == INIT_INITIALIZING);
    assert(!namespace_mutation_allowed(&model, "\\\\Device\\\\Volume\\\\Ycsz\\\\data.db", true));
    assert(namespace_mutation_allowed(&model, "\\\\Device\\\\Volume\\\\other\\\\data.db", true));
    assert(!commit(&model, 10, 101, 1));
    assert(model.state == INIT_INITIALIZING);

    // A stream-marking failure cannot be hidden by a large marked count.
    record_stream(&model, 10, 102, true);
    record_stream(&model, 10, 102, false);
    assert(!commit(&model, 10, 103, 1));
    assert(model.state != INIT_ACTIVE);
    assert(abort_init(&model, 10));
    assert(model.state == INIT_IDLE);

    // A complete scan commits, while a live Active instance cannot be replaced.
    assert(begin(&model, 10, 200));
    record_stream(&model, 10, 201, true);
    assert(commit(&model, 10, 202, 1));
    assert(model.state == INIT_ACTIVE);
    assert(!begin(&model, 11, 203));
    assert(model.state == INIT_ACTIVE);

    // Timeout recovery is allowed only for the stale initializing state.
    reset(&model);
    assert(begin(&model, 20, 300));
    assert(begin(&model, 21, 421));
    assert(model.state == INIT_INITIALIZING && model.owner == 21);
    puts("PASS initialization barrier, failure accounting, namespace guard, stable-active and timeout recovery scenarios");
    return 0;
}
