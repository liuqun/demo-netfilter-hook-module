#ifndef NLEXAMPLE_H
#define NLEXAMPLE_H

enum nlexample_msg_types {
   NLEX_CMD_UPD = 0,
   NLEX_CMD_GET = 1,
   NLEX_CMD_MAX
};

enum nlexample_attr {
   NLE_UNSPEC,
   NLE_MYVAR,
   __NLE_MAX,
};
#define NLE_MAX (__NLE_MAX - 1)

#define NLEX_GRP_MYVAR 1

#endif
