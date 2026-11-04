// Amber (琥珀币) PoW shard grinder — C port of grind_shard.py for GitHub Actions.
// Finds nonces; never sends txs.
//
// Construction (validated in ~/workspace/amber-check/PREP.md, 13/13 real miner
// nonces, and by grind_shard.py reproducing nonce 457589469 exactly):
//   H1 = keccak256(abi.encode(currentSeed, miner))
//   valid iff keccak256(abi.encode(H1, nonce)) <= currentTarget
// Defaults below are the live 2026-11-04 values (seed from contract storage
// slot 9, target 2^226 - 1, miner = wallet 1).
//
// The keccak-f[1600] core is copied verbatim from the Chip404 project's
// miner3.c, whose round constants were selftest-verified against Python
// after a manual-typo fix (see ~/workspace/chip404-dist/).
//
// Usage:
//   grind_shard --start <int> --count <int> [--need 1] [--shard N]
//               [--threads N] [--out results.jsonl]
//   grind_shard --selftest          verify nonce 457589469 reproduces, exit 0/1
//   grind_shard --bench <secs>      hash flat-out for <secs>, report H/s
//
// Every find is printed as "FOUND nonce=<n> hash=0x<64hex>" AND appended
// (flush) to the results file as one JSON line in the batch_w1.jsonl schema:
// {"nonce": int, "hash": "0x…", "miner": "0x…", "source": "gh-c-<shard>",
//  "recorded_at": "…"} — so collect.py can merge results unchanged.
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

// ---------------- keccak-f[1600] (verbatim from chip404-dist/miner3.c) -------
#define ROTL64(x,y) (((x)<<(y))|((x)>>(64-(y))))
static const uint64_t RNDC[24] = {
 0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
 0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
 0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
 0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
 0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
 0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
static const int ROTC[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const int PILN[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

static void keccakf(uint64_t st[25]){
  uint64_t bc[5], t;
  for(int round=0; round<24; round++){
    for(int i=0;i<5;i++) bc[i]=st[i]^st[i+5]^st[i+10]^st[i+15]^st[i+20];
    for(int i=0;i<5;i++){ t=bc[(i+4)%5]^ROTL64(bc[(i+1)%5],1); for(int j=0;j<25;j+=5) st[j+i]^=t; }
    t=st[1];
    for(int i=0;i<24;i++){ int j=PILN[i]; bc[0]=st[j]; st[j]=ROTL64(t,ROTC[i]); t=bc[0]; }
    for(int j=0;j<25;j+=5){
      for(int i=0;i<5;i++) bc[i]=st[j+i];
      for(int i=0;i<5;i++) st[j+i]^=(~bc[(i+1)%5])&bc[(i+2)%5];
    }
    st[0]^=RNDC[round];
  }
}

// One-block keccak256 for messages up to 135 bytes (rate 136, pad 0x01..0x80).
static void keccak256(const uint8_t* msg, size_t len, uint8_t out[32]){
  uint64_t A[25]; memset(A,0,sizeof A);
  uint8_t blk[136]; memset(blk,0,136);
  memcpy(blk,msg,len); blk[len]=0x01; blk[135]|=0x80;
  for(int i=0;i<17;i++){ uint64_t v=0; for(int j=0;j<8;j++) v|=(uint64_t)blk[8*i+j]<<(8*j); A[i]=v; }
  keccakf(A);
  for(int i=0;i<4;i++){ uint64_t v=A[i]; for(int j=0;j<8;j++) out[8*i+j]=(uint8_t)(v>>(8*j)); }
}

// ---------------- Amber parameters (live 2026-11-04) -----------------------
// seed = 1171936696677116967947855102463325820488726368244161564174682728594779209803
static const uint8_t SEED32[32] = {
 0x02,0x97,0x4a,0xec,0x09,0x0a,0x1d,0xc2,0x71,0xd8,0xec,0xee,0xf4,0x07,0xb9,0x7a,
 0x74,0xf2,0x45,0x2e,0x80,0x09,0xa2,0x4c,0xab,0x3b,0xf7,0x2b,0xc9,0x49,0x00,0x4b};
static const char* MINER_HEX = "0xD6bE25e654A516c875AFFD2BBF116bB08179908c";
static const uint8_t MINER20[20] = {
 0xD6,0xBE,0x25,0xe6,0x54,0xA5,0x16,0xc8,0x75,0xAF,0xFD,0x2B,0xBF,0x11,0x6b,0xB0,
 0x81,0x79,0x90,0x8c};
// target = 2^226 - 1, as four big-endian 64-bit words of the 256-bit integer.
static const uint64_t TARGET_W[4] = {
 0x00000003FFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
// Known solution (batch_w1.jsonl / PREP.md) for --selftest.
static const uint64_t SELFTEST_NONCE = 457589469ULL;
static const char* SELFTEST_H1 =
 "f0f31a43207f6bd834924781d83556070d6ce6ae066e51b31b74306a3acac473";
static const char* SELFTEST_HASH =
 "0000000203f5c0eb2677cf0d5b64c7cf0e7a32a4d3949589cb64ea15b54124d3";

static uint8_t H1[32];
static uint64_t BASE[25]; // state template: H1 lanes + padding, nonce lane patched per try

static void compute_h1(void){
  uint8_t msg[64];
  memcpy(msg, SEED32, 32);
  memset(msg+32, 0, 12);            // abi.encode(address): left-pad to 32 bytes
  memcpy(msg+44, MINER20, 20);
  keccak256(msg, 64, H1);
}
static void build_base(void){
  memset(BASE, 0, sizeof BASE);
  for(int i=0;i<4;i++){ uint64_t v=0; for(int j=0;j<8;j++) v|=(uint64_t)H1[8*i+j]<<(8*j); BASE[i]=v; }
  // lanes 4..6 = 0 (nonce uint256 high bytes); lane 7 patched per nonce.
  BASE[8]  = 0x01ULL;               // byte 64 = 0x01 (pad start)
  BASE[16] = 0x8000000000000000ULL; // byte 135 = 0x80 (pad end)
}
static inline void hash_nonce(uint64_t nonce, uint64_t A[25]){
  memcpy(A, BASE, sizeof(uint64_t)*25);
  A[7] = __builtin_bswap64(nonce);  // nonce as uint256 BE in bytes 56..63
  keccakf(A);
}
static inline int meets_target(const uint64_t A[25]){
  // Exact 256-bit compare: digest (big-endian words) <= TARGET_W.
  for(int i=0;i<4;i++){
    uint64_t w = __builtin_bswap64(A[i]);
    if(w < TARGET_W[i]) return 1;
    if(w > TARGET_W[i]) return 0;
  }
  return 1; // exactly equal
}
static void hash_hex(const uint64_t A[25], char out[65]){
  static const char* HXD = "0123456789abcdef";
  for(int i=0;i<32;i++){
    uint8_t b = (uint8_t)(A[i/8] >> (8*(i%8)));
    out[2*i] = HXD[b>>4]; out[2*i+1] = HXD[b&15];
  }
  out[64] = 0;
}

// ---------------- grinding ---------------------------------------------------
static uint64_t G_START, G_COUNT;
static int G_NEED, G_THREADS;
static const char* G_OUT = "results.jsonl";
static char G_SOURCE[64] = "gh-c";
static atomic_int FOUND_COUNT, STOP_FLAG;
static atomic_ullong TRIED;
static pthread_mutex_t OUT_MUTEX = PTHREAD_MUTEX_INITIALIZER;

static void record_found(uint64_t nonce, const uint64_t A[25]){
  char hx[65]; hash_hex(A, hx);
  pthread_mutex_lock(&OUT_MUTEX);
  int c = atomic_fetch_add(&FOUND_COUNT, 1);
  if(c < G_NEED){
    printf("FOUND nonce=%llu hash=0x%s\n", (unsigned long long)nonce, hx);
    fflush(stdout);
    FILE* f = fopen(G_OUT, "a");
    if(f){
      char ts[32]; time_t t = time(NULL); struct tm tmv;
      gmtime_r(&t, &tmv); strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%S+00:00", &tmv);
      fprintf(f, "{\"nonce\": %llu, \"hash\": \"0x%s\", \"miner\": \"%s\", "
                 "\"source\": \"%s\", \"recorded_at\": \"%s\"}\n",
              (unsigned long long)nonce, hx, MINER_HEX, G_SOURCE, ts);
      fflush(f); fsync(fileno(f)); fclose(f);
    }
  }
  if(c + 1 >= G_NEED) atomic_store(&STOP_FLAG, 1);
  pthread_mutex_unlock(&OUT_MUTEX);
}

static void* worker(void* arg){
  long tid = (long)arg;
  uint64_t end = G_START + G_COUNT;
  uint64_t nonce = G_START + (uint64_t)tid;
  uint64_t local = 0;
  uint64_t A[25];
  while(!atomic_load_explicit(&STOP_FLAG, memory_order_relaxed)){
    if(nonce >= end) break;
    hash_nonce(nonce, A);
    if(meets_target(A)) record_found(nonce, A);
    nonce += (uint64_t)G_THREADS; local++;
    if((local & 0xFFFF) == 0){ atomic_fetch_add(&TRIED, local); local = 0; }
  }
  atomic_fetch_add(&TRIED, local);
  return NULL;
}

static double now_s(struct timespec t0){
  struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
  return (t.tv_sec - t0.tv_sec) + (t.tv_nsec - t0.tv_nsec) / 1e9;
}

static int selftest(void){
  compute_h1();
  char h1x[65]; for(int i=0;i<32;i++) sprintf(h1x+2*i, "%02x", H1[i]);
  if(strcmp(h1x, SELFTEST_H1)){ printf("SELFTEST FAIL: H1 %s != %s\n", h1x, SELFTEST_H1); return 1; }
  build_base();
  uint64_t A[25]; hash_nonce(SELFTEST_NONCE, A);
  char hx[65]; hash_hex(A, hx);
  if(strcmp(hx, SELFTEST_HASH)){ printf("SELFTEST FAIL: hash %s != %s\n", hx, SELFTEST_HASH); return 1; }
  if(!meets_target(A)){ printf("SELFTEST FAIL: known nonce does not meet target\n"); return 1; }
  printf("SELFTEST PASS: nonce %llu -> 0x%s (<= target 2^226-1, 30 leading zero bits)\n",
         (unsigned long long)SELFTEST_NONCE, hx);
  return 0;
}

static atomic_ullong BENCH_COUNT;
static atomic_int BENCH_STOP;
static void* bench_worker(void* arg){
  long tid = (long)arg;
  uint64_t nonce = (uint64_t)tid * (1ULL<<40);
  uint64_t local = 0; uint64_t A[25];
  while(!atomic_load_explicit(&BENCH_STOP, memory_order_relaxed)){
    for(int k=0;k<4096;k++){ hash_nonce(nonce++, A); }
    local += 4096; atomic_fetch_add(&BENCH_COUNT, local); local = 0;
  }
  (void)A;
  return NULL;
}
static int bench(double secs, int threads){
  compute_h1(); build_base();
  pthread_t* th = malloc(sizeof(pthread_t)*threads);
  struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
  for(long i=0;i<threads;i++) pthread_create(&th[i], NULL, bench_worker, (void*)i);
  struct timespec ts = { (time_t)secs, (long)((secs - (time_t)secs) * 1e9) };
  nanosleep(&ts, NULL);
  atomic_store(&BENCH_STOP, 1);
  for(int i=0;i<threads;i++) pthread_join(th[i], NULL);
  double el = now_s(t0);
  unsigned long long n = atomic_load(&BENCH_COUNT);
  printf("BENCH threads=%d tried=%llu elapsed=%.1fs aggregate=%.0f h/s per-thread=%.0f h/s\n",
         threads, n, el, n/el, n/el/threads);
  free(th);
  return 0;
}

int main(int argc, char** argv){
  G_START = 0; G_COUNT = 1ULL<<40; G_NEED = 1; G_THREADS = 0;
  double bench_secs = 0;
  char shardbuf[32] = "";
  for(int i=1;i<argc;i++){
    if(!strcmp(argv[i],"--start") && i+1<argc) G_START = strtoull(argv[++i], NULL, 0);
    else if(!strcmp(argv[i],"--count") && i+1<argc) G_COUNT = strtoull(argv[++i], NULL, 0);
    else if(!strcmp(argv[i],"--need") && i+1<argc) G_NEED = atoi(argv[++i]);
    else if(!strcmp(argv[i],"--threads") && i+1<argc) G_THREADS = atoi(argv[++i]);
    else if(!strcmp(argv[i],"--shard") && i+1<argc) snprintf(shardbuf, sizeof shardbuf, "%s", argv[++i]);
    else if(!strcmp(argv[i],"--out") && i+1<argc) G_OUT = argv[++i];
    else if(!strcmp(argv[i],"--bench") && i+1<argc) bench_secs = atof(argv[++i]);
    else if(!strcmp(argv[i],"--selftest")) return selftest();
    else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
  }
  if(G_THREADS <= 0){
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    G_THREADS = n > 0 ? (int)n : 2;
  }
  if(shardbuf[0]) snprintf(G_SOURCE, sizeof G_SOURCE, "gh-c-%s", shardbuf);

  if(bench_secs > 0) return bench(bench_secs, G_THREADS);

  compute_h1(); build_base();
  printf("grind start=%llu count=%llu need=%d threads=%d source=%s miner=%s out=%s\n",
         (unsigned long long)G_START, (unsigned long long)G_COUNT, G_NEED,
         G_THREADS, G_SOURCE, MINER_HEX, G_OUT);
  fflush(stdout);

  pthread_t* th = malloc(sizeof(pthread_t)*G_THREADS);
  struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
  for(long i=0;i<G_THREADS;i++) pthread_create(&th[i], NULL, worker, (void*)i);

  // progress reporter: poll until workers finish (FOUND target or range end)
  int done = 0;
  while(!done){
    struct timespec ts = {5, 0}; nanosleep(&ts, NULL);
    double el = now_s(t0);
    unsigned long long tr = atomic_load(&TRIED);
    int fc = atomic_load(&FOUND_COUNT);
    printf("  ...%llu nonces tried, %.0f h/s, %d/%d found, %.0fs elapsed\n",
           tr, el > 0 ? tr/el : 0, fc, G_NEED, el);
    fflush(stdout);
    if(atomic_load(&STOP_FLAG)) break;
    if(tr >= G_COUNT) break; // TRIED lags slightly; final join check below decides
    // if all threads exited (range exhausted), TRIED stops moving:
    static unsigned long long prev = 0; static int still = 0;
    if(tr == prev && tr > 0){ if(++still >= 2) done = 1; } else { still = 0; prev = tr; }
  }
  atomic_store(&STOP_FLAG, 1);
  for(int i=0;i<G_THREADS;i++) pthread_join(th[i], NULL);
  double el = now_s(t0);
  unsigned long long tr = atomic_load(&TRIED);
  int fc = atomic_load(&FOUND_COUNT);
  printf("DONE found=%d tried=%llu in %.0fs (%.0f h/s avg)\n",
         fc, tr, el, el > 0 ? tr/el : 0);
  fflush(stdout);
  free(th);
  return 0;
}
