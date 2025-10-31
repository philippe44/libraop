// pairing.h
#pragma once
#ifdef __cplusplus
extern "C"
{
#endif
    bool AppleTVpairing(struct mdnssd_handle_s *mDNShandle, char **pSecret, const char *target_ip, int port);
#ifdef __cplusplus
}
#endif