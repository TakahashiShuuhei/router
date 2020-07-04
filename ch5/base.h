typedef struct {
    int soc;
    u_char hwaddr[6];
    struct in_addr addr, subnet, netmask;
} DEVICE;

#define FLAG_FREE 0
#define FLAG_OK 1
#define FLAG_NG -1

/**
 * 双方向リスト
 */
typedef struct _data_buf_{
    struct _data_buf_ *next;
    struct _data_buf_ *before;
    time_t t;
    int size;
    unsigned char *data;
} DATA_BUF;

/**
 * 送信待ちデータを表す構造体
 */
typedef struct {
    DATA_BUF *top;
    DATA_BUF *bottom;
    unsigned long dno;
    unsigned long inBucketSize;
    pthread_mutex_t mutex;
} SEND_DATA;

/**
 * IPアドレスとMACアドレスの関係付のための構造体
 * MACアドレスが不明ならARPで調べる必要がある → 待っている間は送信待ちデータとしてバッファに格納
 * もしARPがタイムアウトしたら送信待ちデータも破棄する
 */
typedef struct {
    int flag;
    int deviceNo;
    in_addr_t addr;
    unsigned char hwaddr[6];
    time_t lastTime;
    SEND_DATA sd;
} IP2MAC;