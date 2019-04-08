#ifndef MY_GENLMSG_HANDLER_H
#define MY_GENLMSG_HANDLER_H

/**
 * Register message handler (based on genl)
 */
int my_genlmsg_handler_register(void);

/**
 * un-register message handler
 */
void my_genlmsg_handler_unregister(void);

#endif /* MY_GENLMSG_HANDLER_H */
