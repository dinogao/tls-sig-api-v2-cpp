#ifndef TLS_SIG_API_V2_H
#define TLS_SIG_API_V2_H

#if defined(WIN32) || defined(WIN64)
#pragma warning(disable : 4819)  // file codec warning, that's boring!
#define TLS_API __declspec(dllexport)
#else
#define TLS_API
#endif

#include <stdint.h>
#include <string>

enum {
  CHECK_ERR01 = 1,  // sig is empty
  CHECK_ERR02,      // sig base64 decode fail
  CHECK_ERR03,      // sig zip decompression failed
  CHECK_ERR04,      // sig failed when parsing using json
  CHECK_ERR05,      // sig failed when parsing using json
  CHECK_ERR06,      // sig field  base64 decode fail in the json string
  CHECK_ERR07,      // fields missing in sig
  CHECK_ERR08,      // sig failed to verify the signature, usually because the secret key is incorrect
  CHECK_ERR09,      // sig expire
  CHECK_ERR10,      // sig failed when parsing using json
  CHECK_ERR11,      // appid_at_3rd in sig does not match the plaintext
  CHECK_ERR12,      // acctype in sig does not match the plaintext
  CHECK_ERR13,      // identifier in sig does not match the plaintext
  CHECK_ERR14,      // sdk_appid in sig does not match the plaintext
  CHECK_ERR15,      // abnormal userbuf in sig
  CHECK_ERR16,      // internal Error
  CHECK_ERR17,      // signature failed, usually due to an error in the private key
  CHECK_ERR_MAX,
};

/**
 * Function: Used to issue UserSig that is required by the TRTC and IM services.
 *
 * Parameter description:
 * @param sdkappid - Application ID
 * @param userid - User ID. The value can be up to 32 bytes in length and contain letters (a-z and A-Z), digits (0-9), underscores (_), and hyphens (-).
 * @param key - The encryption key used to calculate usersig can be obtained from the console.
 * @param expire - UserSig expiration time, in seconds. For example, 86400 indicates that the generated UserSig will expire one day after being generated.
 * @param usersig - Generated signature.
 * @param errmsg - error message.
 * @return 0 for success, non-0 for failure
 */

TLS_API int genUserSig(uint32_t sdkappid, const std::string &userid, const std::string &key, int expire,
                       std::string &usersig, std::string &errmsg);

/**
 * Function:
 * Used to issue PrivateMapKey that is optional for room entry.
 * PrivateMapKey must be used together with UserSig but with more powerful permission control capabilities.
 *  - UserSig can only control whether a UserID has permission to use the TRTC service. As long as the UserSig is correct, the user with the corresponding UserID can enter or leave any room.
 *  - PrivateMapKey specifies more stringent permissions for a UserID, including whether the UserID can be used to enter a specific room and perform audio/video upstreaming in the room.
 * To enable stringent PrivateMapKey permission bit verification, you need to enable permission key in TRTC console > Application Management > Application Info.
 *
 * Parameter description:
 * @param sdkappid - Application ID
 * @param userid - User ID. The value can be up to 32 bytes in length and contain letters (a-z and A-Z), digits (0-9), underscores (_), and hyphens (-).
 * @param key - The encryption key used to calculate usersig can be obtained from the console.
 * @param roomid - ID of the room to which the specified UserID can enter.
 * @param expire - PrivateMapKey expiration time, in seconds. For example, 86400 indicates that the generated PrivateMapKey will expire one day after being generated.
 * @param privilegeMap - Permission bits. Eight bits in the same byte are used as the permission switches of eight specific features:
 *  - Bit 1: 0000 0001 = 1, permission for room creation
 *  - Bit 2: 0000 0010 = 2, permission for room entry
 *  - Bit 3: 0000 0100 = 4, permission for audio sending
 *  - Bit 4: 0000 1000 = 8, permission for audio receiving
 *  - Bit 5: 0001 0000 = 16, permission for video sending
 *  - Bit 6: 0010 0000 = 32, permission for video receiving
 *  - Bit 7: 0100 0000 = 64, permission for substream video sending (screen sharing)
 *  - Bit 8: 1000 0000 = 200, permission for substream video receiving (screen sharing)
 *  - privilegeMap == 1111 1111 == 255: Indicates that the UserID has all feature permissions of the room specified by roomid.
 *  - privilegeMap == 0010 1010 == 42: Indicates that the UserID has only the permissions to enter the room and receive audio/video data.
 * @param usersig -Generated signature
 * @param errmsg - error message.
 * @return 0 for success, non-0 for failure
 */

TLS_API int genPrivateMapKey(uint32_t sdkappid, const std::string &userid, const std::string &key, uint32_t roomid,
                             int expire, int privilegeMap, std::string &usersig, std::string &errmsg);

/**
 * Function:
 * Used to issue PrivateMapKey that is optional for room entry.
 * PrivateMapKey must be used together with UserSig but with more powerful permission control capabilities.
 *  - UserSig can only control whether a UserID has permission to use the TRTC service. As long as the UserSig is correct, the user with the corresponding UserID can enter or leave any room.
 *  - PrivateMapKey specifies more stringent permissions for a UserID, including whether the UserID can be used to enter a specific room and perform audio/video upstreaming in the room.
 * To enable stringent PrivateMapKey permission bit verification, you need to enable permission key in TRTC console > Application Management > Application Info.
 *
 * Parameter description:
 * @param sdkappid - Application ID
 * @param userid - User ID. The value can be up to 32 bytes in length and contain letters (a-z and A-Z), digits (0-9), underscores (_), and hyphens (-).
 * @param key - The encryption key used to calculate usersig can be obtained from the console.
 * @param roomstr - ID of the room to which the specified UserID can enter.
 * @param expire - PrivateMapKey expiration time, in seconds. For example, 86400 indicates that the generated PrivateMapKey will expire one day after being generated.
 * @param privilegeMap - Permission bits. Eight bits in the same byte are used as the permission switches of eight specific features:
 *  - Bit 1: 0000 0001 = 1, permission for room creation
 *  - Bit 2: 0000 0010 = 2, permission for room entry
 *  - Bit 3: 0000 0100 = 4, permission for audio sending
 *  - Bit 4: 0000 1000 = 8, permission for audio receiving
 *  - Bit 5: 0001 0000 = 16, permission for video sending
 *  - Bit 6: 0010 0000 = 32, permission for video receiving
 *  - Bit 7: 0100 0000 = 64, permission for substream video sending (screen sharing)
 *  - Bit 8: 1000 0000 = 200, permission for substream video receiving (screen sharing)
 *  - privilegeMap == 1111 1111 == 255: Indicates that the UserID has all feature permissions of the room specified by roomid.
 *  - privilegeMap == 0010 1010 == 42: Indicates that the UserID has only the permissions to enter the room and receive audio/video data.
 * @param usersig - Generated signature
 * @param errmsg - error message.
 * @return 0 for success, non-0 for failure
 */

TLS_API int genPrivateMapKeyWithStringRoomID(uint32_t sdkappid, const std::string &userid, const std::string &key,
                                             const std::string &roomstr, int expire, int privilegeMap,
                                             std::string &usersig, std::string &errmsg);

TLS_API std::string gen_userbuf(const std::string &account, uint32_t dwSdkappid, uint32_t dwAuthID, uint32_t dwExpTime,
                                uint32_t dwPrivilegeMap, uint32_t dwAccountType, const std::string &roomStr);

TLS_API int genSig(uint32_t sdkappid, const std::string &userid, const std::string &key, const std::string &userbuf,
                   int expire, std::string &usersig, std::string &errmsg);
int thread_setup();
void thread_cleanup();

#endif  // TLS_SIG_API_V2_H
