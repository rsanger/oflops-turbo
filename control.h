#ifndef CONTROL_H
#define CONTROL_H

#include "oflops.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Setup the control channel based on the configuration details
 * of the context. 
 */
int setup_control_channel(oflops_context *ctx);
void teardown_control_channel(oflops_context *ctx);
int write_oflops_control(oflops_context *ctx, void* data, size_t len);
int has_backlog(oflops_context *ctx);

#ifdef __cplusplus
}
#endif
#endif
