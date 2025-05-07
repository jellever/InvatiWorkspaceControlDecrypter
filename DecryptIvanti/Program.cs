using RES.Kernel.Drivers;
using RES.WorkspaceManager.Common;
using RES.WorkspaceManager.PInvoke;
using RES.WorkspaceManager.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace DecryptIvanti
{
    internal static class Program
    {

        private static TResult Decrypt<TResult>(Func<char[], TResult> toResultFunc, string value, char[] password, bool shortEncryption, bool pysnSilent = false)
        {
            try
            {
                bool flag = value.Length == 0;
                if (flag)
                {
                    return toResultFunc(new char[0]);
                }
                bool flag2 = password.Length != 0;
                if (flag2)
                {
                    int num = 0;
                    char[] array;
                    if (shortEncryption)
                    {
                        bool flag3 = value.Length % 2 != 0;
                        if (flag3)
                        {
                            return toResultFunc(value.ToCharArray());
                        }
                        array = new char[value.Length / 2];
                        for (int i = 0; i < value.Length; i += 2)
                        {
                            int num2 = value.Substring(i, 2).HexToInt();
                            num2 -= (int)password[(i / 2 + 1) % password.Length];
                            array[num] = num2.ToChar();
                            num++;
                        }
                    }
                    else
                    {
                        bool flag4 = value.Length % 4 != 0;
                        if (flag4)
                        {
                            return toResultFunc(value.ToCharArray());
                        }
                        array = new char[value.Length / 4];
                        for (int j = 0; j < value.Length; j += 4)
                        {
                            int num2 = value.Substring(j, 4).HexToInt();
                            num2 -= (int)password[(j / 4 + 1) % password.Length];
                            array[num] = num2.ToChar();
                            num++;
                        }
                    }
                    return toResultFunc(array);
                }
                return toResultFunc(value.ToCharArray());
            }
            catch (Exception ex)
            {
                bool flag5 = !pysnSilent;
                if (flag5)
                {
                    //sharedErrHandler.ShowError("Decrypt", ex, false);
                }
            }
            return toResultFunc(new char[0]);
        }

        public static SecureString DecryptToSecureString(string strText, SecureString pwd, bool ysnShort, bool pysnSilent = false)
        {
            byte[] bytes = pwd.GetBytes();
            char[] chars = Encoding.Unicode.GetChars(bytes);
            SecureString secureString = Decrypt<SecureString>((char[] charArray) => charArray.ToSecureString(), strText, chars, ysnShort, pysnSilent);
            Array.Clear(chars, 0, chars.Length);
            Array.Clear(bytes, 0, bytes.Length);
            return secureString;
        }

        public static SecureString DecryptToSecureString(string strText, enuSecureKey encryptionKey, bool ysnShort, bool pysnSilent = false)
        {
            SecureString secureString;
            using (SecureString encryptionKey2 = GetEncryptionKey(encryptionKey))
            {
                secureString = DecryptToSecureString(strText, encryptionKey2, ysnShort, pysnSilent);
            }
            return secureString;
        }

        public static SecureString GetEncryptionKey(enuSecureKey encryptionKey)
        {
            SecureString secureString = new SecureString();
            switch (encryptionKey)
            {
                case enuSecureKey.Key_AGFiles:
                    secureString.AppendChar('T');
                    secureString.AppendChar('h');
                    secureString.AppendChar('e');
                    secureString.AppendChar('W');
                    secureString.AppendChar('i');
                    secureString.AppendChar('z');
                    secureString.AppendChar('a');
                    secureString.AppendChar('r');
                    secureString.AppendChar('d');
                    secureString.AppendChar('O');
                    secureString.AppendChar('f');
                    secureString.AppendChar('O');
                    secureString.AppendChar('z');
                    break;
                case enuSecureKey.Key_TxtPasswords:
                    secureString.AppendChar('D');
                    secureString.AppendChar('e');
                    secureString.AppendChar('L');
                    secureString.AppendChar('i');
                    secureString.AppendChar('j');
                    secureString.AppendChar('s');
                    secureString.AppendChar('t');
                    secureString.AppendChar('V');
                    secureString.AppendChar('a');
                    secureString.AppendChar('n');
                    secureString.AppendChar('7');
                    break;
                case enuSecureKey.Key_MappingPassword:
                    secureString.AppendChar('n');
                    secureString.AppendChar('i');
                    secureString.AppendChar('h');
                    secureString.AppendChar('o');
                    secureString.AppendChar('n');
                    secureString.AppendChar('g');
                    secureString.AppendChar('o');
                    secureString.AppendChar('n');
                    secureString.AppendChar('o');
                    secureString.AppendChar('k');
                    secureString.AppendChar('a');
                    secureString.AppendChar('g');
                    secureString.AppendChar('i');
                    break;
                case enuSecureKey.Key_PowerMail:
                    secureString.AppendChar('H');
                    secureString.AppendChar('e');
                    secureString.AppendChar('r');
                    secureString.AppendChar('m');
                    secureString.AppendChar('e');
                    secureString.AppendChar('s');
                    secureString.AppendChar('7');
                    secureString.AppendChar('5');
                    break;
                case enuSecureKey.Key_CachedCredential:
                    secureString.AppendChar('F');
                    secureString.AppendChar('r');
                    secureString.AppendChar('e');
                    secureString.AppendChar('e');
                    secureString.AppendChar('A');
                    secureString.AppendChar('s');
                    secureString.AppendChar('A');
                    secureString.AppendChar('B');
                    secureString.AppendChar('i');
                    secureString.AppendChar('r');
                    secureString.AppendChar('d');
                    break;
                case enuSecureKey.Key_AppV:
                    secureString.AppendChar('W');
                    secureString.AppendChar('h');
                    secureString.AppendChar('i');
                    secureString.AppendChar('s');
                    secureString.AppendChar('k');
                    secureString.AppendChar('e');
                    secureString.AppendChar('y');
                    secureString.AppendChar('I');
                    secureString.AppendChar('n');
                    secureString.AppendChar('T');
                    secureString.AppendChar('h');
                    secureString.AppendChar('e');
                    secureString.AppendChar('J');
                    secureString.AppendChar('a');
                    secureString.AppendChar('r');
                    break;
                case enuSecureKey.Key_ADPassword:
                    secureString.AppendChar('E');
                    secureString.AppendChar('n');
                    secureString.AppendChar('c');
                    secureString.AppendChar('r');
                    secureString.AppendChar('y');
                    secureString.AppendChar('p');
                    secureString.AppendChar('t');
                    secureString.AppendChar('i');
                    secureString.AppendChar('o');
                    secureString.AppendChar('n');
                    secureString.AppendChar('F');
                    secureString.AppendChar('o');
                    secureString.AppendChar('r');
                    secureString.AppendChar('D');
                    secureString.AppendChar('u');
                    secureString.AppendChar('m');
                    secureString.AppendChar('m');
                    secureString.AppendChar('i');
                    secureString.AppendChar('e');
                    secureString.AppendChar('s');
                    break;
                case enuSecureKey.Key_NamedLics:
                    secureString.AppendChar('J');
                    secureString.AppendChar('u');
                    secureString.AppendChar('s');
                    secureString.AppendChar('t');
                    secureString.AppendChar('S');
                    secureString.AppendChar('a');
                    secureString.AppendChar('y');
                    secureString.AppendChar('Y');
                    secureString.AppendChar('e');
                    secureString.AppendChar('s');
                    secureString.AppendChar('2');
                    secureString.AppendChar('0');
                    secureString.AppendChar('1');
                    secureString.AppendChar('0');
                    break;
                case enuSecureKey.Key_Landesk:
                    secureString.AppendChar('D');
                    secureString.AppendChar('r');
                    secureString.AppendChar('a');
                    secureString.AppendChar('g');
                    secureString.AppendChar('o');
                    secureString.AppendChar('n');
                    secureString.AppendChar('R');
                    secureString.AppendChar('e');
                    secureString.AppendChar('b');
                    secureString.AppendChar('o');
                    secureString.AppendChar('r');
                    secureString.AppendChar('n');
                    break;
                case enuSecureKey.Key_EmergencyPassword:
                    secureString.AppendChar('N');
                    secureString.AppendChar('o');
                    secureString.AppendChar('S');
                    secureString.AppendChar('n');
                    secureString.AppendChar('e');
                    secureString.AppendChar('a');
                    secureString.AppendChar('k');
                    secureString.AppendChar('y');
                    secureString.AppendChar('E');
                    secureString.AppendChar('x');
                    secureString.AppendChar('i');
                    secureString.AppendChar('t');
                    secureString.AppendChar('s');
                    break;
                case enuSecureKey.Key_UserPassword:
                    secureString.AppendChar('K');
                    secureString.AppendChar('i');
                    secureString.AppendChar('d');
                    secureString.AppendChar('d');
                    secureString.AppendChar('o');
                    break;
                case enuSecureKey.Key_PFRPHeader:
                    secureString.AppendChar('D');
                    secureString.AppendChar('r');
                    secureString.AppendChar('a');
                    secureString.AppendChar('i');
                    secureString.AppendChar('n');
                    secureString.AppendChar('i');
                    secureString.AppendChar('n');
                    secureString.AppendChar('g');
                    secureString.AppendChar('T');
                    secureString.AppendChar('h');
                    secureString.AppendChar('e');
                    secureString.AppendChar('S');
                    secureString.AppendChar('w');
                    secureString.AppendChar('a');
                    secureString.AppendChar('m');
                    secureString.AppendChar('p');
                    break;
                case enuSecureKey.Key_SiteID:
                    secureString.AppendChar('M');
                    secureString.AppendChar('i');
                    secureString.AppendChar('l');
                    secureString.AppendChar('l');
                    secureString.AppendChar('e');
                    secureString.AppendChar('n');
                    secureString.AppendChar('i');
                    secureString.AppendChar('u');
                    secureString.AppendChar('m');
                    break;
                case enuSecureKey.Key_ConnectionConfig:
                    secureString.AppendChar('B');
                    secureString.AppendChar('i');
                    secureString.AppendChar('n');
                    secureString.AppendChar('c');
                    secureString.AppendChar('k');
                    secureString.AppendChar('2');
                    secureString.AppendChar('0');
                    secureString.AppendChar('0');
                    secureString.AppendChar('9');
                    break;
                case enuSecureKey.Key_License:
                    secureString.AppendChar('A');
                    secureString.AppendChar('n');
                    secureString.AppendChar('a');
                    secureString.AppendChar('s');
                    secureString.AppendChar('t');
                    secureString.AppendChar('a');
                    secureString.AppendChar('s');
                    secureString.AppendChar('i');
                    secureString.AppendChar('a');
                    break;
                case enuSecureKey.Key_DBCredentials:
                    secureString.AppendChar('V');
                    secureString.AppendChar('e');
                    secureString.AppendChar('e');
                    secureString.AppendChar('l');
                    secureString.AppendChar('G');
                    secureString.AppendChar('o');
                    secureString.AppendChar('e');
                    secureString.AppendChar('d');
                    secureString.AppendChar('e');
                    secureString.AppendChar('r');
                    break;
                case enuSecureKey.Key_Alerting:
                    secureString.AppendChar('A');
                    secureString.AppendChar('t');
                    secureString.AppendChar('r');
                    secureString.AppendChar('e');
                    secureString.AppendChar('i');
                    secureString.AppendChar('d');
                    secureString.AppendChar('e');
                    secureString.AppendChar('s');
                    break;
                case enuSecureKey.Key_DBUid:
                    secureString.AppendChar('A');
                    secureString.AppendChar('t');
                    secureString.AppendChar('t');
                    secureString.AppendChar('a');
                    secureString.AppendChar('c');
                    secureString.AppendChar('k');
                    secureString.AppendChar('O');
                    secureString.AppendChar('f');
                    secureString.AppendChar('T');
                    secureString.AppendChar('h');
                    secureString.AppendChar('e');
                    secureString.AppendChar('C');
                    secureString.AppendChar('l');
                    secureString.AppendChar('o');
                    secureString.AppendChar('n');
                    secureString.AppendChar('e');
                    secureString.AppendChar('s');
                    break;
                case enuSecureKey.Key_DBSecondaryPassword:
                    secureString.AppendChar('D');
                    secureString.AppendChar('a');
                    secureString.AppendChar('r');
                    secureString.AppendChar('t');
                    secureString.AppendChar('h');
                    secureString.AppendChar('T');
                    secureString.AppendChar('a');
                    secureString.AppendChar('l');
                    secureString.AppendChar('o');
                    secureString.AppendChar('n');
                    break;
                case enuSecureKey.Key_UserPreferences:
                    secureString.AppendChar('G');
                    secureString.AppendChar('r');
                    secureString.AppendChar('e');
                    secureString.AppendChar('e');
                    secureString.AppendChar('n');
                    secureString.AppendChar('l');
                    secureString.AppendChar('e');
                    secureString.AppendChar('a');
                    secureString.AppendChar('f');
                    break;
                case enuSecureKey.Key_Subscriber:
                    secureString.AppendChar('T');
                    secureString.AppendChar('h');
                    secureString.AppendChar('e');
                    secureString.AppendChar('T');
                    secureString.AppendChar('r');
                    secureString.AppendChar('u');
                    secureString.AppendChar('t');
                    secureString.AppendChar('h');
                    secureString.AppendChar('I');
                    secureString.AppendChar('s');
                    secureString.AppendChar('O');
                    secureString.AppendChar('u');
                    secureString.AppendChar('t');
                    secureString.AppendChar('T');
                    secureString.AppendChar('h');
                    secureString.AppendChar('e');
                    secureString.AppendChar('r');
                    secureString.AppendChar('e');
                    break;
                case enuSecureKey.Key_PwrtraceUser:
                    secureString.AppendChar('B');
                    secureString.AppendChar('i');
                    secureString.AppendChar('g');
                    secureString.AppendChar('B');
                    secureString.AppendChar('r');
                    secureString.AppendChar('o');
                    secureString.AppendChar('t');
                    secureString.AppendChar('h');
                    secureString.AppendChar('e');
                    secureString.AppendChar('r');
                    secureString.AppendChar('I');
                    secureString.AppendChar('s');
                    secureString.AppendChar('W');
                    secureString.AppendChar('a');
                    secureString.AppendChar('t');
                    secureString.AppendChar('c');
                    secureString.AppendChar('h');
                    secureString.AppendChar('i');
                    secureString.AppendChar('n');
                    secureString.AppendChar('g');
                    break;
                case enuSecureKey.Key_UnmanagedApps:
                    secureString.AppendChar('C');
                    secureString.AppendChar('r');
                    secureString.AppendChar('y');
                    secureString.AppendChar('s');
                    secureString.AppendChar('t');
                    secureString.AppendChar('a');
                    secureString.AppendChar('l');
                    secureString.AppendChar('B');
                    secureString.AppendChar('a');
                    secureString.AppendChar('l');
                    secureString.AppendChar('l');
                    break;
                case enuSecureKey.Key_XenAppCredentials:
                    secureString.AppendChar('C');
                    secureString.AppendChar('r');
                    secureString.AppendChar('y');
                    secureString.AppendChar('s');
                    secureString.AppendChar('t');
                    secureString.AppendChar('a');
                    secureString.AppendChar('l');
                    secureString.AppendChar('b');
                    secureString.AppendChar('a');
                    secureString.AppendChar('l');
                    secureString.AppendChar('l');
                    secureString.AppendChar('1');
                    secureString.AppendChar('2');
                    secureString.AppendChar('3');
                    secureString.AppendChar('!');
                    break;
                case enuSecureKey.Key_PwrtraceData:
                    secureString.AppendChar('J');
                    secureString.AppendChar('e');
                    secureString.AppendChar('r');
                    secureString.AppendChar('r');
                    secureString.AppendChar('y');
                    secureString.AppendChar('M');
                    secureString.AppendChar('a');
                    secureString.AppendChar('g');
                    secureString.AppendChar('u');
                    secureString.AppendChar('i');
                    secureString.AppendChar('r');
                    secureString.AppendChar('e');
                    break;
                case enuSecureKey.Key_PassthruLic:
                    secureString.AppendChar('H');
                    secureString.AppendChar('e');
                    secureString.AppendChar('r');
                    secureString.AppendChar('e');
                    secureString.AppendChar('I');
                    secureString.AppendChar('s');
                    secureString.AppendChar('T');
                    secureString.AppendChar('h');
                    secureString.AppendChar('e');
                    secureString.AppendChar('T');
                    secureString.AppendChar('r');
                    secureString.AppendChar('u');
                    secureString.AppendChar('t');
                    secureString.AppendChar('h');
                    break;
                case enuSecureKey.Key_LicFlexSilver:
                    secureString.AppendChar('A');
                    secureString.AppendChar('r');
                    secureString.AppendChar('g');
                    secureString.AppendChar('e');
                    secureString.AppendChar('n');
                    secureString.AppendChar('t');
                    secureString.AppendChar('u');
                    secureString.AppendChar('m');
                    break;
                case enuSecureKey.Key_PowerMailCredentials:
                    secureString.AppendChar('H');
                    secureString.AppendChar('e');
                    secureString.AppendChar('r');
                    secureString.AppendChar('m');
                    secureString.AppendChar('u');
                    secureString.AppendChar('s');
                    secureString.AppendChar('2');
                    secureString.AppendChar('9');
                    secureString.AppendChar('1');
                    secureString.AppendChar('9');
                    secureString.AppendChar('1');
                    break;
                case enuSecureKey.Key_HyperDrive:
                    secureString.AppendChar('D');
                    secureString.AppendChar('4');
                    secureString.AppendChar('r');
                    secureString.AppendChar('t');
                    secureString.AppendChar('h');
                    secureString.AppendChar('M');
                    secureString.AppendChar('4');
                    secureString.AppendChar('u');
                    secureString.AppendChar('l');
                    break;
                case enuSecureKey.Key_RoidPassword:
                    secureString.AppendChar('1');
                    secureString.AppendChar('7');
                    secureString.AppendChar('0');
                    secureString.AppendChar('4');
                    secureString.AppendChar('1');
                    secureString.AppendChar('9');
                    secureString.AppendChar('6');
                    secureString.AppendChar('2');
                    break;
                case enuSecureKey.Key_RegSiteGuid:
                    secureString.AppendChar('2');
                    secureString.AppendChar('0');
                    secureString.AppendChar('0');
                    secureString.AppendChar('9');
                    secureString.AppendChar('0');
                    secureString.AppendChar('6');
                    secureString.AppendChar('1');
                    secureString.AppendChar('2');
                    break;
                case enuSecureKey.Key_WSPassword:
                    secureString.AppendChar('R');
                    secureString.AppendChar('o');
                    secureString.AppendChar('b');
                    secureString.AppendChar('e');
                    secureString.AppendChar('r');
                    secureString.AppendChar('t');
                    secureString.AppendChar('J');
                    secureString.AppendChar('o');
                    secureString.AppendChar('r');
                    secureString.AppendChar('d');
                    secureString.AppendChar('a');
                    secureString.AppendChar('n');
                    break;
                case enuSecureKey.Key_SiteInfo:
                    secureString.AppendChar('1');
                    secureString.AppendChar('9');
                    secureString.AppendChar('7');
                    secureString.AppendChar('0');
                    secureString.AppendChar('0');
                    secureString.AppendChar('2');
                    secureString.AppendChar('1');
                    secureString.AppendChar('9');
                    break;
                case enuSecureKey.Key_RDCredentials:
                    secureString.AppendChar('C');
                    secureString.AppendChar('r');
                    secureString.AppendChar('y');
                    secureString.AppendChar('s');
                    secureString.AppendChar('t');
                    secureString.AppendChar('a');
                    secureString.AppendChar('l');
                    secureString.AppendChar('b');
                    secureString.AppendChar('a');
                    secureString.AppendChar('l');
                    secureString.AppendChar('l');
                    secureString.AppendChar('1');
                    secureString.AppendChar('2');
                    secureString.AppendChar('3');
                    secureString.AppendChar('!');
                    break;
                case enuSecureKey.Key_CloudCredentials:
                    secureString.AppendChar('R');
                    secureString.AppendChar('e');
                    secureString.AppendChar('g');
                    secureString.AppendChar('O');
                    secureString.AppendChar('p');
                    secureString.AppendChar('e');
                    secureString.AppendChar('n');
                    secureString.AppendChar('K');
                    secureString.AppendChar('e');
                    secureString.AppendChar('y');
                    secureString.AppendChar('(');
                    secureString.AppendChar('s');
                    secureString.AppendChar('t');
                    secureString.AppendChar('r');
                    secureString.AppendChar('K');
                    secureString.AppendChar('e');
                    secureString.AppendChar('y');
                    secureString.AppendChar(')');
                    break;
                default:
                    throw new ArgumentOutOfRangeException("encryptionKey", encryptionKey, null);
            }
            secureString.MakeReadOnly();
            return secureString;
        }

        public enum enuSecureKey
        {
            // Token: 0x040008C6 RID: 2246
            Key_Unknown,
            // Token: 0x040008C7 RID: 2247
            Key_AGFiles,
            // Token: 0x040008C8 RID: 2248
            Key_TxtPasswords,
            // Token: 0x040008C9 RID: 2249
            Key_MappingPassword,
            // Token: 0x040008CA RID: 2250
            Key_PowerMail,
            // Token: 0x040008CB RID: 2251
            Key_CachedCredential,
            // Token: 0x040008CC RID: 2252
            Key_AppV,
            // Token: 0x040008CD RID: 2253
            Key_ADPassword,
            // Token: 0x040008CE RID: 2254
            Key_NamedLics,
            // Token: 0x040008CF RID: 2255
            Key_Landesk,
            // Token: 0x040008D0 RID: 2256
            Key_EmergencyPassword,
            // Token: 0x040008D1 RID: 2257
            Key_UserPassword,
            // Token: 0x040008D2 RID: 2258
            Key_PFRPHeader,
            // Token: 0x040008D3 RID: 2259
            Key_SiteID,
            // Token: 0x040008D4 RID: 2260
            Key_ConnectionConfig,
            // Token: 0x040008D5 RID: 2261
            Key_License,
            // Token: 0x040008D6 RID: 2262
            Key_DBCredentials,
            // Token: 0x040008D7 RID: 2263
            Key_Alerting,
            // Token: 0x040008D8 RID: 2264
            Key_DBUid,
            // Token: 0x040008D9 RID: 2265
            Key_DBSecondaryPassword,
            // Token: 0x040008DA RID: 2266
            Key_UserPreferences,
            // Token: 0x040008DB RID: 2267
            Key_Subscriber,
            // Token: 0x040008DC RID: 2268
            Key_PwrtraceUser,
            // Token: 0x040008DD RID: 2269
            Key_UnmanagedApps,
            // Token: 0x040008DE RID: 2270
            Key_XenAppCredentials,
            // Token: 0x040008DF RID: 2271
            Key_PwrtraceData,
            // Token: 0x040008E0 RID: 2272
            Key_PassthruLic,
            // Token: 0x040008E1 RID: 2273
            Key_LicFlexSilver,
            // Token: 0x040008E2 RID: 2274
            Key_PowerMailCredentials,
            // Token: 0x040008E3 RID: 2275
            Key_HyperDrive,
            // Token: 0x040008E4 RID: 2276
            Key_RoidPassword,
            // Token: 0x040008E5 RID: 2277
            Key_RegSiteGuid,
            // Token: 0x040008E6 RID: 2278
            Key_WSPassword,
            // Token: 0x040008E7 RID: 2279
            Key_SiteInfo,
            // Token: 0x040008E8 RID: 2280
            Key_RDCredentials,
            // Token: 0x040008E9 RID: 2281
            Key_CloudCredentials,
            // Token: 0x040008EA RID: 2282
            Key_Last
        }

        public static SecureString DecryptExToSecureString(string encryptedText, int key, bool salt, bool convertToANSI = true, bool useEnglishLCID = false)
        {
            Func<char[], SecureString> func = (char[] charArray) => charArray.ToSecureString();
            return DecryptEx<SecureString>(func, encryptedText, key, salt, convertToANSI, useEnglishLCID);
        }

        internal static bool fysnDoubleByteCharSet()
        {
            bool flag = false;
            try
            {
                kernel32.CPINFOEX cpinfoex;
                bool cpinfoEx = kernel32.GetCPInfoEx(out cpinfoex);
                if (cpinfoEx)
                {
                    int codePage = cpinfoex.CodePage;
                    if (codePage == 932 || codePage == 936 || codePage - 949 <= 1)
                    {
                        flag = true;
                    }
                }
            }
            catch (Exception ex)
            {
                sharedErrHandler.ShowError("sharedDBCS.fysnDoubleByteCharSet", ex, false);
            }
            return flag;
        }

        // Token: 0x06000C3E RID: 3134 RVA: 0x000AD670 File Offset: 0x000AB870
        private static byte[] StringToByteArray(string input)
        {
            byte[] array = null;
            try
            {
                array = input.ToByteArray();
            }
            catch (Exception ex)
            {
                sharedErrHandler.ShowError("StringToByteArray", ex, false);
            }
            return array;
        }

        // Token: 0x06000C40 RID: 3136 RVA: 0x000AD9F8 File Offset: 0x000ABBF8
        private static byte[] DecryptExPrivate(byte[] encrypted, long key, bool salt)
        {
            byte[] array = new byte[0];
            try
            {
                long num = 11L + key % 233L;
                long num2 = 7L + key % 239L;
                long num3 = 5L + key % 241L;
                long num4 = 3L + key % 251L;
                byte[] array2 = new byte[encrypted.Length];
                Array.Copy(encrypted, array2, encrypted.Length);
                int num5 = -1;
                int num6 = -1;
                bool flag = array2 != null;
                if (flag)
                {
                    num5 = array2.GetLowerBound(0);
                    num6 = array2.GetUpperBound(0);
                }
                bool flag2 = (num6 == -1 && num5 == -1) || num6 < num5;
                if (flag2)
                {
                    return array;
                }
                for (int i = num5; i <= num6 - 2; i++)
                {
                    array2[i] = (byte)((long)(array2[i] ^ array2[i + 2]) ^ (num4 * (long)((ulong)array2[i + 1]) % 256L));
                }
                for (int j = num6; j >= num5 + 2; j--)
                {
                    array2[j] = (byte)((long)(array2[j] ^ array2[j - 2]) ^ (num3 * (long)((ulong)array2[j - 1]) % 256L));
                }
                for (int k = num5; k <= num6 - 1; k++)
                {
                    array2[k] = (byte)((long)(array2[k] ^ array2[k + 1]) ^ (num2 * (long)((ulong)array2[k + 1]) % 256L));
                }
                for (int l = num6; l >= num5 + 1; l--)
                {
                    array2[l] = (byte)((long)(array2[l] ^ array2[l - 1]) ^ (num * (long)((ulong)array2[l - 1]) % 256L));
                }
                if (salt)
                {
                    bool flag3 = 1 + num6 - num5 > 4;
                    if (flag3)
                    {
                        Array.Copy(array2, num5 + 2, array2, num5, 1 + num6 - num5 - 4);
                        Array.Resize<byte>(ref array2, array2.Length - 4);
                        array = array2;
                    }
                    else
                    {
                        bool flag4 = 1 + num6 - num5 == 4;
                        if (flag4)
                        {
                        }
                    }
                }
                else
                {
                    array = array2;
                }
            }
            catch (Exception ex)
            {
                sharedErrHandler.ShowError("DecryptExPrivate", ex, false);
            }
            return array;
        }

        private static string ByteArrayToString(byte[] input)
        {
            string text = string.Empty;
            try
            {
                text = input.ByteArrayToString();
            }
            catch (Exception ex)
            {
                sharedErrHandler.ShowError("ByteArrayToString", ex, false);
            }
            return text;
        }

        private static TResult DecryptEx<TResult>(Func<char[], TResult> toResultFunc, string encryptedText, int key, bool salt, bool convertToANSI = true, bool useEnglishLCID = false)
        {
            try
            {
                bool flag = fysnDoubleByteCharSet();
                int num = (useEnglishLCID ? 1252 : 0);
                byte[] array;
                if (convertToANSI)
                {
                    bool flag2 = flag || useEnglishLCID;
                    if (flag2)
                    {
                        array = Encoding.GetEncoding(num).GetBytes(encryptedText);
                    }
                    else
                    {
                        array = Encoding.Default.GetBytes(encryptedText);
                    }
                }
                else
                {
                    array = StringToByteArray(encryptedText);
                }
                array = DecryptExPrivate(array, (long)key, salt);
                char[] array2;
                if (convertToANSI)
                {
                    bool flag3 = flag || useEnglishLCID;
                    if (flag3)
                    {
                        array2 = Encoding.GetEncoding(num).GetChars(array);
                    }
                    else
                    {
                        array2 = Encoding.Default.GetChars(array);
                    }
                }
                else
                {
                    array2 = ByteArrayToString(array).ToCharArray();
                }
                return toResultFunc(array2);
            }
            catch (Exception ex)
            {
                sharedErrHandler.ShowError("DecryptEx", ex, false);
            }
            return toResultFunc(new char[0]);
        }

        internal static string fstrDecodeXML64(string pstrString)
        {
            string text = pstrString;
            try
            {
                byte[] array = Convert.FromBase64String(pstrString);
                text = array.ByteArrayToString();
            }
            catch
            {
            }
            return text;
        }

        internal class DbConnectionSettings 
        {
            // Token: 0x170000AF RID: 175
            // (get) Token: 0x0600033E RID: 830 RVA: 0x0003FCC7 File Offset: 0x0003DEC7
            // (set) Token: 0x0600033F RID: 831 RVA: 0x0003FCCF File Offset: 0x0003DECF
            public DbType DBType { get; set; }

            // Token: 0x170000B0 RID: 176
            // (get) Token: 0x06000340 RID: 832 RVA: 0x0003FCD8 File Offset: 0x0003DED8
            // (set) Token: 0x06000341 RID: 833 RVA: 0x0003FCE0 File Offset: 0x0003DEE0
            public string Datasource { get; set; }

            // Token: 0x170000B1 RID: 177
            // (get) Token: 0x06000342 RID: 834 RVA: 0x0003FCE9 File Offset: 0x0003DEE9
            // (set) Token: 0x06000343 RID: 835 RVA: 0x0003FCF1 File Offset: 0x0003DEF1
            public string DatabaseName { get; set; }

            // Token: 0x170000B2 RID: 178
            // (get) Token: 0x06000344 RID: 836 RVA: 0x0003FCFA File Offset: 0x0003DEFA
            // (set) Token: 0x06000345 RID: 837 RVA: 0x0003FD02 File Offset: 0x0003DF02
            public string Username { get; set; }

            // Token: 0x170000B3 RID: 179
            // (get) Token: 0x06000346 RID: 838 RVA: 0x0003FD0B File Offset: 0x0003DF0B
            // (set) Token: 0x06000347 RID: 839 RVA: 0x0003FD13 File Offset: 0x0003DF13
            public SecureString Password { get; set; }

            // Token: 0x170000B4 RID: 180
            // (get) Token: 0x06000348 RID: 840 RVA: 0x0003FD1C File Offset: 0x0003DF1C
            // (set) Token: 0x06000349 RID: 841 RVA: 0x0003FD24 File Offset: 0x0003DF24
            public DbProtocolEncryption ProtocolEncryption { get; set; }

            // Token: 0x0600034A RID: 842 RVA: 0x0003FD30 File Offset: 0x0003DF30
            public DbConnectionSettings()
            {
                this.DBType = DbType.MSSQL;
                this.Datasource = string.Empty;
                this.DatabaseName = string.Empty;
                this.Username = string.Empty;
                this.Password = new SecureString();
                this.ProtocolEncryption = DbProtocolEncryption.Disabled;
            }

            public override string ToString()
            {
                return $"DBType:\t{this.DBType}\n" +
                    $"Datasoute:\t{this.Datasource}\n" +
                    $"DatabaseName:\t{this.DatabaseName}\n" +
                    $"Username:\t{this.Username}\n" +
                    $"Password:\t{this.Password.ToNormalString()}\n" +
                    $"ProtocolEncryption:\t{this.ProtocolEncryption}\n";
                return base.ToString();
            }
        }

        internal enum enuEncryptionPrefix
        {
            // Token: 0x04000902 RID: 2306
            PrefixNONE,
            // Token: 0x04000903 RID: 2307
            PrefixFIPS
        }

        internal static string fstrGetEncryptionPrefix(enuEncryptionPrefix pPrefix)
        {
            try
            {
                string text = string.Empty;
                if (pPrefix == enuEncryptionPrefix.PrefixFIPS)
                {
                    text = "FIPS";
                }
                return "!" + text + "=";
            }
            catch (Exception ex)
            {
                sharedErrHandler.ShowError("sharedEncryption.fstrGetEncryptionPrefix", ex, false);
            }
            return string.Empty;
        }

        internal static bool fysnIsFIPSEncryptedValue(string pstrValue)
        {
            bool flag = false;
            try
            {
                bool flag2 = pstrValue.StartsWith(fstrGetEncryptionPrefix(enuEncryptionPrefix.PrefixFIPS));
                if (flag2)
                {
                    flag = true;
                }
            }
            catch (Exception ex)
            {
                sharedErrHandler.ShowError("sharedEncryption.fysnIsFIPSEncryptedValue", ex, false);
            }
            return flag;
        }

        // Token: 0x06000C3C RID: 3132 RVA: 0x000AD5E8 File Offset: 0x000AB7E8
        internal static string fstrDecryptEx(string encryptedText, int key, bool salt, bool convertToANSI = true, bool useEnglishLCID = false)
        {
            Func<char[], string> func = (char[] charArray) => new string(charArray.ToArray<char>());
            return DecryptEx<string>(func, encryptedText, key, salt, convertToANSI, useEnglishLCID);
        }

        public static DbType ToDbType(this string dbType)
        {
            string text = (dbType ?? string.Empty).Trim().ToUpper();
            DbType dbType2;
            if (!(text == "ORACLE"))
            {
                if (!(text == "DB2"))
                {
                    if (!(text == "MYSQL"))
                    {
                        if (!(text == "MSSQLAZURE"))
                        {
                            dbType2 = DbType.MSSQL;
                        }
                        else
                        {
                            dbType2 = DbType.MSSQLAZURE;
                        }
                    }
                    else
                    {
                        dbType2 = DbType.MYSQL;
                    }
                }
                else
                {
                    dbType2 = DbType.DB2;
                }
            }
            else
            {
                dbType2 = DbType.ORACLE;
            }
            return dbType2;
        }

        internal static bool fysnGetConnectionSettingsFromDHCPString(string DHCPString, out DbConnectionSettings dbConnectionSettings, out string siteGUID)
        {
            bool flag = false;
            siteGUID = string.Empty;
            DbConnectionSettings dbConnectionSettings2 = new DbConnectionSettings();
            try
            {
                string[] array = DHCPString.SplitLikeVB(new char[] { ';' });
                bool flag2 = array.Length == 6;
                if (flag2)
                {
                    dbConnectionSettings2.DBType = array[0].Replace("RESPFDB=", string.Empty).fstrTrimNull().ToDbType();
                    dbConnectionSettings2.Datasource = array[1].fstrTrimNull();
                    dbConnectionSettings2.DatabaseName = array[2].fstrTrimNull();
                    SecureString secureString = new SecureString();
                    try
                    {
                        bool flag3 = fysnIsFIPSEncryptedValue(array[3]);
                        if (flag3)
                        {
                            //secureString = sharedEncryption.DecryptFIPSToSecureString(array[3], sharedEncryption.enuEncryptionKey.Key_DHCP);
                            //siteGUID = sharedEncryption.fstrDecryptFIPS(array[5], sharedEncryption.enuEncryptionKey.Key_DHCP).fstrTrimNull();
                        }
                        else
                        {
                            secureString = DecryptExToSecureString(fstrDecodeXML64(array[3]), 20090612, true, false, false);
                            siteGUID = fstrDecryptEx(fstrDecodeXML64(array[5]), 20090612, true, false, false).fstrTrimNull();
                        }
                    }
                    catch
                    {
                    }
                    SecureString[] array2 = secureString.Split(new char[] { ';' }, 2);
                    bool flag4 = array2.Length > 1;
                    if (flag4)
                    {
                        dbConnectionSettings2.Username = array2[0].ToNormalString();
                        dbConnectionSettings2.Password = array2[1];
                        flag = true;
                    }
                    dbConnectionSettings2.ProtocolEncryption = DbProtocolEncryptionHelper.FromIntValue(array[4].ToInt());
                }
                else
                {
                    Tracing.Trace("fysnGetConnectionSettingsFromDHCPString", "settingsArray.Length = " + array.Length.ToString(), true, Array.Empty<Tracing.enuTraceClass>());
                }
            }
            catch (Exception ex)
            {
                sharedErrHandler.ShowError("fysnGetConnectionSettingsFromDHCPString", ex, false);
            }
            finally
            {
                dbConnectionSettings = dbConnectionSettings2;
            }
            return flag;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Please enter the (encrypted) Ivanti Workspace Control Agent connection string: ");
            string filecont = Console.ReadLine();
            DbConnectionSettings settings = new DbConnectionSettings();
            string siteGuid;
            fysnGetConnectionSettingsFromDHCPString(filecont, out settings, out  siteGuid);

            Console.WriteLine($"Input: {filecont}");
            Console.WriteLine($"Details:\n{settings.ToString()}");
            Console.Read();
            




        }
    }
}
