#define MODULE_LOG_PREFIX "ecmbin"
#include "globals.h"

#ifdef WITH_ECMBIN
#include "oscam-client.h"
#include "oscam-config.h"
#include "oscam-reader.h"
#include "oscam-string.h"

#define CW_SIZE 16
#define HASH_SIZE 8192
#define INITIAL_CAPACITY 64
#define MAX_FILES 1024
#define CS_OK    1
#define CS_ERROR 0
#define CR_OK    0
#define CR_ERROR 1
#ifndef MAP_POPULATE
#define MAP_POPULATE 0
#endif

static inline uint32_t fnv1a_hash(const uint8_t *data, size_t len) {
    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}

struct ecm_entry {
    uint8_t *ecm_data;
    uint8_t cw[CW_SIZE];
    uint32_t hash;
    struct ecm_entry *next;
};

struct ecm_file {
    struct ecm_entry **hash_table;
    uint8_t *mmap_data;
    size_t file_size;
    size_t num_entries;
    uint16_t caid;
    uint16_t srvid;
    pthread_rwlock_t lock;
};

struct ecmbin_data {
    struct ecm_file *files;
    uint64_t *keys;
    size_t count;
    size_t capacity;
    uint8_t ecm_size;
    pthread_rwlock_t lock;
};

static inline uint64_t make_key(uint16_t caid, uint16_t srvid) {
    return ((uint64_t)caid << 32) | srvid;
}

static int key_compare(const void *a, const void *b) {
    uint64_t ka = *(const uint64_t*)a;
    uint64_t kb = *(const uint64_t*)b;
    if (ka < kb) return -1;
    if (ka > kb) return 1;
    return 0;
}

static struct ecm_file* find_file(struct ecmbin_data *data, uint16_t caid, uint16_t srvid) {
    uint64_t key = make_key(caid, srvid);
    uint64_t *found = bsearch(&key, data->keys, data->count, sizeof(uint64_t), key_compare);
    if (!found) return NULL;
    size_t index = found - data->keys;
    return &data->files[index];
}

static inline int parse_filename(const char *name, uint16_t *caid, uint16_t *srvid) {
    size_t len = strlen(name);
    if (len < 13) return 0;
    if (strcasecmp(name + len - 4, ".bin")) return 0;
    char base[32];
    if (snprintf(base, sizeof(base), "%.*s", (int)(len - 4), name) >= (int)sizeof(base))
        return 0;
    return sscanf(base, "%04hX@%04hX", caid, srvid) == 2;
}

static int ensure_capacity(struct ecmbin_data *data) {
    if (data->count < data->capacity) return 1;
    size_t new_cap = data->capacity ? data->capacity * 2 : INITIAL_CAPACITY;
    if (new_cap > MAX_FILES) new_cap = MAX_FILES;
    struct ecm_file *new_files = realloc(data->files, new_cap * sizeof(struct ecm_file));
    uint64_t *new_keys = realloc(data->keys, new_cap * sizeof(uint64_t));
    if (!new_files || !new_keys) {
        free(new_files);
        free(new_keys);
        return 0;
    }
    data->files = new_files;
    data->keys = new_keys;
    data->capacity = new_cap;
    return 1;
}

static int load_file(struct ecmbin_data *data, const char *path, uint16_t caid, uint16_t srvid) {
    if (!ensure_capacity(data)) return 0;
    int fd = open(path, O_RDONLY);
    if (fd == -1) return 0;
    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        return 0;
    }
    size_t entry_size = data->ecm_size + CW_SIZE;
    if (st.st_size % entry_size) {
        close(fd);
        return 0;
    }
    uint8_t *mmap_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
    close(fd);
    if (mmap_data == MAP_FAILED) return 0;
    madvise(mmap_data, st.st_size, MADV_SEQUENTIAL);
    struct ecm_file *file = &data->files[data->count];
    memset(file, 0, sizeof(*file));
    file->mmap_data = mmap_data;
    file->file_size = st.st_size;
    file->caid = caid;
    file->srvid = srvid;
    file->num_entries = st.st_size / entry_size;
    file->hash_table = calloc(HASH_SIZE, sizeof(struct ecm_entry*));
    if (!file->hash_table) {
        munmap(mmap_data, st.st_size);
        return 0;
    }
    pthread_rwlock_init(&file->lock, NULL);
    struct ecm_entry *entries = malloc(file->num_entries * sizeof(struct ecm_entry));
    if (!entries) {
        munmap(mmap_data, st.st_size);
        free(file->hash_table);
        return 0;
    }
    for (size_t i = 0; i < file->num_entries; i++) {
        uint8_t *entry_data = mmap_data + (i * entry_size);
        struct ecm_entry *entry = &entries[i];
        entry->ecm_data = entry_data;
        memcpy(entry->cw, entry_data + data->ecm_size, CW_SIZE);
        entry->hash = fnv1a_hash(entry_data, data->ecm_size);
        uint32_t idx = entry->hash % HASH_SIZE;
        entry->next = file->hash_table[idx];
        file->hash_table[idx] = entry;
    }
    data->keys[data->count] = make_key(caid, srvid);
    data->count++;
    cs_log("Loaded [%04hX@%04hX.bin] entries: %zu", caid, srvid, file->num_entries);
    return 1;
}

static void load_all_files(struct s_reader *reader) {
    struct ecmbin_data *data = reader->csystem_data;

    data->ecm_size = reader->ecm_end - reader->ecm_start;
    if (data->ecm_size == 0 || data->ecm_size > 200) {
        cs_log("Invalid ECM range (%d-%d) in %s", reader->ecm_start, reader->ecm_end, reader->label);
        return;
    }

    const char *folder = reader->ecm_path;
    if (!folder || access(folder, R_OK)) {
        cs_log("Cannot access ECM folder %s", folder ? folder : "NULL");
        return;
    }

    data->capacity = INITIAL_CAPACITY;
    data->files = malloc(data->capacity * sizeof(struct ecm_file));
    data->keys = malloc(data->capacity * sizeof(uint64_t));
    if (!data->files || !data->keys) {
        free(data->files);
        free(data->keys);
        return;
    }
    memset(data->files, 0, data->capacity * sizeof(struct ecm_file));

    DIR *dir = opendir(folder);
    if (!dir) {
        free(data->files);
        free(data->keys);
        return;
    }

    struct dirent *entry;
    char path[512];
    while ((entry = readdir(dir)) && data->count < MAX_FILES) {
        uint16_t caid, srvid;
        if (entry->d_name[0] == '.' || !parse_filename(entry->d_name, &caid, &srvid)) continue;
        snprintf(path, sizeof(path), "%s/%s", folder, entry->d_name);
        load_file(data, path, caid, srvid);
    }
    closedir(dir);

    qsort(data->keys, data->count, sizeof(uint64_t), key_compare);
    cs_log("Loaded %zu ECM files from %s (range %d-%d)", data->count, folder, reader->ecm_start, reader->ecm_end);
}

static int32_t search_ecm(struct ecm_file *file, const uint8_t *ecm, size_t ecm_size, struct s_ecm_answer *ea) {
    uint32_t hash = fnv1a_hash(ecm, ecm_size);
    struct ecm_entry *entry = file->hash_table[hash % HASH_SIZE];
    while (entry) {
        if (entry->hash == hash && !memcmp(ecm, entry->ecm_data, ecm_size)) {
            memcpy(ea->cw, entry->cw, CW_SIZE);
            return CS_OK;
        }
        entry = entry->next;
    }
    return CS_ERROR;
}

static void cleanup_data(struct ecmbin_data *data) {
    if (!data) return;
    for (size_t i = 0; i < data->count; i++) {
        struct ecm_file *file = &data->files[i];
        if (file->hash_table) {
            for (size_t j = 0; j < HASH_SIZE; j++) {
                if (file->hash_table[j]) {
                    free(file->hash_table[j]);
                    break;
                }
            }
            free(file->hash_table);
        }
        if (file->mmap_data) munmap(file->mmap_data, file->file_size);
        pthread_rwlock_destroy(&file->lock);
    }
    free(data->files);
    free(data->keys);
    pthread_rwlock_destroy(&data->lock);
}

static int32_t ecmbin_do_ecm(struct s_reader *rdr, const ECM_REQUEST *er, struct s_ecm_answer *ea) {
    struct ecmbin_data *data = rdr->csystem_data;
    if (!data) return CS_ERROR;
    pthread_rwlock_rdlock(&data->lock);
    struct ecm_file *file = find_file(data, er->caid, er->srvid);
    if (!file) {
        pthread_rwlock_unlock(&data->lock);
        return CS_ERROR;
    }
    pthread_rwlock_rdlock(&file->lock);
    pthread_rwlock_unlock(&data->lock);
    int32_t result = search_ecm(file, &er->ecm[rdr->ecm_start], data->ecm_size, ea);
    pthread_rwlock_unlock(&file->lock);
    return result;
}

static int32_t ecmbin_card_info(struct s_reader *rdr) {
    if (!rdr->csystem_data) {
        rdr->csystem_data = calloc(1, sizeof(struct ecmbin_data));
        if (!rdr->csystem_data) return CS_ERROR;
        pthread_rwlock_init(&((struct ecmbin_data*)rdr->csystem_data)->lock, NULL);
        load_all_files(rdr);
    }
    rdr->card_status = CARD_INSERTED;
    return CS_OK;
}

static void ecmbin_card_done(struct s_reader *rdr) {
    if (rdr->csystem_data) {
        cleanup_data(rdr->csystem_data);
        free(rdr->csystem_data);
        rdr->csystem_data = NULL;
    }
}

const struct s_cardsystem reader_ecmbin = {
    .desc = "ecmbin",
    .caids = (uint16_t[]){ 0x0B, 0 },
    .do_ecm = ecmbin_do_ecm,
    .card_info = ecmbin_card_info,
    .card_done = ecmbin_card_done,
};

static int32_t ecmbin_reader_init(struct s_reader *reader) {
    reader->csystem = &reader_ecmbin;
    return CR_OK;
}

static int32_t ecmbin_close(struct s_reader *reader) {
    if (reader->csystem_data) {
        cleanup_data(reader->csystem_data);
        free(reader->csystem_data);
        reader->csystem_data = NULL;
    }
    return CR_OK;
}

static int32_t ecmbin_get_status(struct s_reader *UNUSED(reader), int32_t *in) { *in = 1; return CR_OK; }
static int32_t ecmbin_activate(struct s_reader *UNUSED(reader), struct s_ATR *UNUSED(atr)) { return CR_OK; }
static int32_t ecmbin_transmit(struct s_reader *UNUSED(reader), uint8_t *UNUSED(buffer), uint32_t UNUSED(size), uint32_t UNUSED(expectedlen), uint32_t UNUSED(delay), uint32_t UNUSED(timeout)) { return CR_OK; }
static int32_t ecmbin_receive(struct s_reader *UNUSED(reader), uint8_t *UNUSED(buffer), uint32_t UNUSED(size), uint32_t UNUSED(delay), uint32_t UNUSED(timeout)) { return CR_OK; }
static int32_t ecmbin_write_settings(struct s_reader *UNUSED(reader), struct s_cardreader_settings *UNUSED(settings)) { return CR_OK; }
static int32_t ecmbin_card_write(struct s_reader *UNUSED(reader), const uint8_t *UNUSED(buf), uint8_t *UNUSED(cta_res), uint16_t *UNUSED(cta_lr), int32_t UNUSED(len)) { return CR_OK; }
static int32_t ecmbin_set_protocol(struct s_reader *UNUSED(reader), uint8_t *UNUSED(params), uint32_t *UNUSED(length), uint32_t UNUSED(len_request)) { return CR_OK; }

const struct s_cardreader cardreader_ecmbin = {
    .desc = "ecmbin",
    .typ = R_ECMBIN,
	.skip_extra_atr_parsing = 1,
    .reader_init = ecmbin_reader_init,
    .get_status = ecmbin_get_status,
    .activate = ecmbin_activate,
    .transmit = ecmbin_transmit,
    .receive = ecmbin_receive,
    .close = ecmbin_close,
    .write_settings = ecmbin_write_settings,
    .card_write = ecmbin_card_write,
    .set_protocol = ecmbin_set_protocol,
};

void add_ecmbin_reader(void) {
    LL_ITER itr = ll_iter_create(configured_readers);
    struct s_reader *rdr;
    while ((rdr = ll_iter_next(&itr))) {
        if (rdr->typ == R_ECMBIN) return;
    }
    if (cs_malloc(&rdr, sizeof(struct s_reader))) {
        reader_set_defaults(rdr);
        rdr->enable = 1;
        rdr->typ = R_ECMBIN;
        cs_strncpy(rdr->label, "Ecmbin", sizeof(rdr->label));
		cs_strncpy(rdr->device, "Virtual", sizeof(rdr->device));
        rdr->grp = 0x2ULL;
        rdr->crdr = &cardreader_ecmbin;
        reader_fixups_fn(rdr);
        ll_append(configured_readers, rdr);
    }
}
#endif
