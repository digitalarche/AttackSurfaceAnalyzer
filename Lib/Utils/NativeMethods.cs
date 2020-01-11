﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Serilog;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace AttackSurfaceAnalyzer.Utils
{
    /// <summary>
    /// The TOKEN_INFORMATION_CLASS enumeration type contains values that 
    /// specify the type of information being assigned to or retrieved from 
    /// an access token.
    /// </summary>
    internal enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        MaxTokenInfoClass
    }

    /// <summary>
    /// The WELL_KNOWN_SID_TYPE enumeration type is a list of commonly used 
    /// security identifiers (SIDs). Programs can pass these values to the 
    /// CreateWellKnownSid function to create a SID from this list.
    /// </summary>
    internal enum WELL_KNOWN_SID_TYPE
    {
        WinNullSid = 0,
        WinWorldSid = 1,
        WinLocalSid = 2,
        WinCreatorOwnerSid = 3,
        WinCreatorGroupSid = 4,
        WinCreatorOwnerServerSid = 5,
        WinCreatorGroupServerSid = 6,
        WinNtAuthoritySid = 7,
        WinDialupSid = 8,
        WinNetworkSid = 9,
        WinBatchSid = 10,
        WinInteractiveSid = 11,
        WinServiceSid = 12,
        WinAnonymousSid = 13,
        WinProxySid = 14,
        WinEnterpriseControllersSid = 15,
        WinSelfSid = 16,
        WinAuthenticatedUserSid = 17,
        WinRestrictedCodeSid = 18,
        WinTerminalServerSid = 19,
        WinRemoteLogonIdSid = 20,
        WinLogonIdsSid = 21,
        WinLocalSystemSid = 22,
        WinLocalServiceSid = 23,
        WinNetworkServiceSid = 24,
        WinBuiltinDomainSid = 25,
        WinBuiltinAdministratorsSid = 26,
        WinBuiltinUsersSid = 27,
        WinBuiltinGuestsSid = 28,
        WinBuiltinPowerUsersSid = 29,
        WinBuiltinAccountOperatorsSid = 30,
        WinBuiltinSystemOperatorsSid = 31,
        WinBuiltinPrintOperatorsSid = 32,
        WinBuiltinBackupOperatorsSid = 33,
        WinBuiltinReplicatorSid = 34,
        WinBuiltinPreWindows2000CompatibleAccessSid = 35,
        WinBuiltinRemoteDesktopUsersSid = 36,
        WinBuiltinNetworkConfigurationOperatorsSid = 37,
        WinAccountAdministratorSid = 38,
        WinAccountGuestSid = 39,
        WinAccountKrbtgtSid = 40,
        WinAccountDomainAdminsSid = 41,
        WinAccountDomainUsersSid = 42,
        WinAccountDomainGuestsSid = 43,
        WinAccountComputersSid = 44,
        WinAccountControllersSid = 45,
        WinAccountCertAdminsSid = 46,
        WinAccountSchemaAdminsSid = 47,
        WinAccountEnterpriseAdminsSid = 48,
        WinAccountPolicyAdminsSid = 49,
        WinAccountRasAndIasServersSid = 50,
        WinNTLMAuthenticationSid = 51,
        WinDigestAuthenticationSid = 52,
        WinSChannelAuthenticationSid = 53,
        WinThisOrganizationSid = 54,
        WinOtherOrganizationSid = 55,
        WinBuiltinIncomingForestTrustBuildersSid = 56,
        WinBuiltinPerfMonitoringUsersSid = 57,
        WinBuiltinPerfLoggingUsersSid = 58,
        WinBuiltinAuthorizationAccessSid = 59,
        WinBuiltinTerminalServerLicenseServersSid = 60,
        WinBuiltinDCOMUsersSid = 61,
        WinBuiltinIUsersSid = 62,
        WinIUserSid = 63,
        WinBuiltinCryptoOperatorsSid = 64,
        WinUntrustedLabelSid = 65,
        WinLowLabelSid = 66,
        WinMediumLabelSid = 67,
        WinHighLabelSid = 68,
        WinSystemLabelSid = 69,
        WinWriteRestrictedCodeSid = 70,
        WinCreatorOwnerRightsSid = 71,
        WinCacheablePrincipalsGroupSid = 72,
        WinNonCacheablePrincipalsGroupSid = 73,
        WinEnterpriseReadonlyControllersSid = 74,
        WinAccountReadonlyControllersSid = 75,
        WinBuiltinEventLogReadersGroup = 76,
        WinNewEnterpriseReadonlyControllersSid = 77,
        WinBuiltinCertSvcDComAccessGroup = 78
    }

    /// <summary>
    /// The SECURITY_IMPERSONATION_LEVEL enumeration type contains values 
    /// that specify security impersonation levels. Security impersonation 
    /// levels govern the degree to which a server process can act on behalf 
    /// of a client process.
    /// </summary>
    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    /// <summary>
    /// The TOKEN_ELEVATION_TYPE enumeration indicates the elevation type of 
    /// token being queried by the GetTokenInformation function or set by 
    /// the SetTokenInformation function.
    /// </summary>
    internal enum TOKEN_ELEVATION_TYPE
    {
        TokenElevationTypeDefault = 1,
        TokenElevationTypeFull,
        TokenElevationTypeLimited
    }

    /// <summary>
    /// The structure represents a security identifier (SID) and its 
    /// attributes. SIDs are used to uniquely identify users or groups.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public UInt32 Attributes;
    }

    /// <summary>
    /// The structure indicates whether a token has elevated privileges.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_ELEVATION
    {
        public Int32 TokenIsElevated;
    }

    /// <summary>
    /// The structure specifies the mandatory integrity level for a token.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    internal class NativeMethods
    {

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);
        // Token Specific Access Rights

        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE |
            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES |
            TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);


        public const Int32 ERROR_INSUFFICIENT_BUFFER = 122;


        // Integrity Levels

        public const Int32 SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000;
        public const Int32 SECURITY_MANDATORY_LOW_RID = 0x00001000;
        public const Int32 SECURITY_MANDATORY_MEDIUM_RID = 0x00002000;
        public const Int32 SECURITY_MANDATORY_HIGH_RID = 0x00003000;
        public const Int32 SECURITY_MANDATORY_SYSTEM_RID = 0x00004000;


        /// <summary>
        /// The function opens the access token associated with a process.
        /// </summary>
        /// <param name="hProcess">
        /// A handle to the process whose access token is opened.
        /// </param>
        /// <param name="desiredAccess">
        /// Specifies an access mask that specifies the requested types of 
        /// access to the access token. 
        /// </param>
        /// <param name="hToken">
        /// Outputs a handle that identifies the newly opened access token 
        /// when the function returns.
        /// </param>
        /// <returns></returns>
        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr hProcess,
            UInt32 desiredAccess, out SafeTokenHandle hToken);


        /// <summary>
        /// The function creates a new access token that duplicates one 
        /// already in existence.
        /// </summary>
        /// <param name="ExistingTokenHandle">
        /// A handle to an access token opened with TOKEN_DUPLICATE access.
        /// </param>
        /// <param name="ImpersonationLevel">
        /// Specifies a SECURITY_IMPERSONATION_LEVEL enumerated type that 
        /// supplies the impersonation level of the new token.
        /// </param>
        /// <param name="DuplicateTokenHandle">
        /// Outputs a handle to the duplicate token. 
        /// </param>
        /// <returns></returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateToken(
            SafeTokenHandle ExistingTokenHandle,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            out SafeTokenHandle DuplicateTokenHandle);


        /// <summary>
        /// The function retrieves a specified type of information about an 
        /// access token. The calling process must have appropriate access 
        /// rights to obtain the information.
        /// </summary>
        /// <param name="hToken">
        /// A handle to an access token from which information is retrieved.
        /// </param>
        /// <param name="tokenInfoClass">
        /// Specifies a value from the TOKEN_INFORMATION_CLASS enumerated 
        /// type to identify the type of information the function retrieves.
        /// </param>
        /// <param name="pTokenInfo">
        /// A pointer to a buffer the function fills with the requested 
        /// information.
        /// </param>
        /// <param name="tokenInfoLength">
        /// Specifies the size, in bytes, of the buffer pointed to by the 
        /// TokenInformation parameter. 
        /// </param>
        /// <param name="returnLength">
        /// A pointer to a variable that receives the number of bytes needed 
        /// for the buffer pointed to by the TokenInformation parameter. 
        /// </param>
        /// <returns></returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            SafeTokenHandle hToken,
            TOKEN_INFORMATION_CLASS tokenInfoClass,
            IntPtr pTokenInfo,
            Int32 tokenInfoLength,
            out Int32 returnLength);


        /// <summary>
        /// Sets the elevation required state for a specified button or 
        /// command link to display an elevated icon. 
        /// </summary>
        public const UInt32 BCM_SETSHIELD = 0x160C;


        /// <summary>
        /// Sends the specified message to a window or windows. The function 
        /// calls the window procedure for the specified window and does not 
        /// return until the window procedure has processed the message. 
        /// </summary>
        /// <param name="hWnd">
        /// Handle to the window whose window procedure will receive the 
        /// message.
        /// </param>
        /// <param name="Msg">Specifies the message to be sent.</param>
        /// <param name="wParam">
        /// Specifies additional message-specific information.
        /// </param>
        /// <param name="lParam">
        /// Specifies additional message-specific information.
        /// </param>
        /// <returns></returns>
        [DllImport("user32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int SendMessage(IntPtr hWnd, UInt32 Msg, int wParam, IntPtr lParam);


        /// <summary>
        /// The function returns a pointer to a specified subauthority in a 
        /// security identifier (SID). The subauthority value is a relative 
        /// identifier (RID).
        /// </summary>
        /// <param name="pSid">
        /// A pointer to the SID structure from which a pointer to a 
        /// subauthority is to be returned.
        /// </param>
        /// <param name="nSubAuthority">
        /// Specifies an index value identifying the subauthority array 
        /// element whose address the function will return.
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is a pointer to the 
        /// specified SID subauthority. To get extended error information, 
        /// call GetLastError. If the function fails, the return value is 
        /// undefined. The function fails if the specified SID structure is 
        /// not valid or if the index value specified by the nSubAuthority 
        /// parameter is out of bounds.
        /// </returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetSidSubAuthority(IntPtr pSid, UInt32 nSubAuthority);

        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        // GUID of the action to perform
        private const string WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        static extern WinVerifyTrustResult WinVerifyTrust(
            [In] IntPtr hwnd,
            [In] [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
            [In] WinTrustData pWVTData
        );

        // call WinTrust.WinVerifyTrust() to check embedded file signature
        [HandleProcessCorruptedStateExceptions]
        [SecurityCritical]
        public static string VerifyEmbeddedSignature(string filename)
        {
            try
            {
                WinTrustFileInfo winTrustFileInfo = null;
                WinTrustData winTrustData = null;

                // specify the WinVerifyTrust function/action that we want
                Guid action = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);

                // instantiate our WinTrustFileInfo and WinTrustData data structures
                winTrustFileInfo = new WinTrustFileInfo(filename);
                winTrustData = new WinTrustData(filename);

                WinVerifyTrustResult result = WinVerifyTrust(INVALID_HANDLE_VALUE, action, winTrustData);
                // call into WinVerifyTrust
                switch (result)
                {
                    case WinVerifyTrustResult.Success:
                        return "Valid";
                    case WinVerifyTrustResult.ProviderUnknown:
                        return "ProviderUnknown";
                    case WinVerifyTrustResult.ActionUnknown:
                        return "ActionUnknown";
                    case WinVerifyTrustResult.SubjectFormUnknown:
                        return "SubjectFormUnknown";
                    case WinVerifyTrustResult.SubjectNotTrusted:
                        return "SubjectNotTrusted";
                    case WinVerifyTrustResult.FileNotSigned:
                        return "FileNotSigned";
                    case WinVerifyTrustResult.SubjectExplicitlyDistrusted:
                        return "SubjectExplicitlyDistrusted";
                    case WinVerifyTrustResult.SignatureOrFileCorrupt:
                        return "SignatureOrFileCorrupt";
                    case WinVerifyTrustResult.SubjectCertExpired:
                        return "SubjectCertExpired";
                    case WinVerifyTrustResult.SubjectCertificateRevoked:
                        return "SubjectCertificateRevoked";
                    case WinVerifyTrustResult.UntrustedRoot:
                        return "UntrustedRoot";
                    default:
                        // The UI was disabled in dwUIChoice or the admin policy 
                        // has disabled user trust. lStatus contains the 
                        // publisher or time stamp chain error.
                        return result.ToString();
                }
            }
            catch (Exception e) when (
                e is System.AccessViolationException
                || e is Exception)
            {
                Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                AsaTelemetry.TrackEvent("VerifyEmbeddedSignatureException", ExceptionEvent);
                return "FailedToFetch";
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WIN32_FILE_ATTRIBUTE_DATA
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
        }

        public enum GET_FILEEX_INFO_LEVELS
        {
            GetFileExInfoStandard,
            GetFileExMaxInfoLevel
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetFileAttributesEx(string lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, out WIN32_FILE_ATTRIBUTE_DATA fileData);

        #region WinTrustData struct field enums
        enum WinTrustDataUIChoice : uint
        {
            All = 1,
            None = 2,
            NoBad = 3,
            NoGood = 4
        }

        enum WinTrustDataRevocationChecks : uint
        {
            None = 0x00000000,
            WholeChain = 0x00000001
        }

        enum WinTrustDataChoice : uint
        {
            File = 1,
            Catalog = 2,
            Blob = 3,
            Signer = 4,
            Certificate = 5
        }

        enum WinTrustDataStateAction : uint
        {
            Ignore = 0x00000000,
            Verify = 0x00000001,
            Close = 0x00000002,
            AutoCache = 0x00000003,
            AutoCacheFlush = 0x00000004
        }

        [FlagsAttribute]
        enum WinTrustDataProvFlags : uint
        {
            UseIe4TrustFlag = 0x00000001,
            NoIe4ChainFlag = 0x00000002,
            NoPolicyUsageFlag = 0x00000004,
            RevocationCheckNone = 0x00000010,
            RevocationCheckEndCert = 0x00000020,
            RevocationCheckChain = 0x00000040,
            RevocationCheckChainExcludeRoot = 0x00000080,
            SaferFlag = 0x00000100,        // Used by software restriction policies. Should not be used.
            HashOnlyFlag = 0x00000200,
            UseDefaultOsverCheck = 0x00000400,
            LifetimeSigningFlag = 0x00000800,
            CacheOnlyUrlRetrieval = 0x00001000,      // affects CRL retrieval and AIA retrieval
            DisableMD2andMD4 = 0x00002000      // Win7 SP1+: Disallows use of MD2 or MD4 in the chain except for the root 
        }

        enum WinTrustDataUIContext : uint
        {
            Execute = 0,
            Install = 1
        }
        #endregion

        #region WinTrust structures
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        class WinTrustFileInfo
        {
            UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustFileInfo));
            IntPtr pszFilePath;                     // required, file name to be verified
            IntPtr hFile = IntPtr.Zero;             // optional, open handle to FilePath
            IntPtr pgKnownSubject = IntPtr.Zero;    // optional, subject type if it is known

            public WinTrustFileInfo(String _filePath)
            {
                pszFilePath = Marshal.StringToCoTaskMemAuto(_filePath);
            }
            ~WinTrustFileInfo()
            {
                Marshal.FreeCoTaskMem(pszFilePath);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        class WinTrustData
        {
            UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustData));
            IntPtr PolicyCallbackData = IntPtr.Zero;
            IntPtr SIPClientData = IntPtr.Zero;
            // required: UI choice
            WinTrustDataUIChoice UIChoice = WinTrustDataUIChoice.None;
            // required: certificate revocation check options
            WinTrustDataRevocationChecks RevocationChecks = WinTrustDataRevocationChecks.None;
            // required: which structure is being passed in?
            WinTrustDataChoice UnionChoice = WinTrustDataChoice.File;
            // individual file
            IntPtr FileInfoPtr;
            WinTrustDataStateAction StateAction = WinTrustDataStateAction.Ignore;
            IntPtr StateData = IntPtr.Zero;
            String URLReference = null;
            WinTrustDataProvFlags ProvFlags = WinTrustDataProvFlags.RevocationCheckChainExcludeRoot;
            WinTrustDataUIContext UIContext = WinTrustDataUIContext.Execute;

            // constructor for silent WinTrustDataChoice.File check
            public WinTrustData(String _fileName)
            {
                // On Win7SP1+, don't allow MD2 or MD4 signatures
                if ((Environment.OSVersion.Version.Major > 6) ||
                    ((Environment.OSVersion.Version.Major == 6) && (Environment.OSVersion.Version.Minor > 1)) ||
                    ((Environment.OSVersion.Version.Major == 6) && (Environment.OSVersion.Version.Minor == 1) && !String.IsNullOrEmpty(Environment.OSVersion.ServicePack)))
                {
                    ProvFlags |= WinTrustDataProvFlags.DisableMD2andMD4;
                }

                WinTrustFileInfo wtfiData = new WinTrustFileInfo(_fileName);
                FileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                Marshal.StructureToPtr(wtfiData, FileInfoPtr, false);
            }
            ~WinTrustData()
            {
                Marshal.FreeCoTaskMem(FileInfoPtr);
            }
        }
        #endregion
        enum WinVerifyTrustResult : uint
        {
            Success = 0,
            ProviderUnknown = 0x800b0001,           // Trust provider is not recognized on this system
            ActionUnknown = 0x800b0002,         // Trust provider does not support the specified action
            SubjectFormUnknown = 0x800b0003,        // Trust provider does not support the form specified for the subject
            SubjectNotTrusted = 0x800b0004,         // Subject failed the specified verification action
            FileNotSigned = 0x800B0100,         // TRUST_E_NOSIGNATURE - File was not signed
            SubjectExplicitlyDistrusted = 0x800B0111,   // Signer's certificate is in the Untrusted Publishers store
            SignatureOrFileCorrupt = 0x80096010,    // TRUST_E_BAD_DIGEST - file was probably corrupt
            SubjectCertExpired = 0x800B0101,        // CERT_E_EXPIRED - Signer's certificate was expired
            SubjectCertificateRevoked = 0x800B010C,     // CERT_E_REVOKED Subject's certificate was revoked
            UntrustedRoot = 0x800B0109          // CERT_E_UNTRUSTEDROOT - A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider.
        }

        private const uint FILE_READ_EA = 0x0008;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x2000000;

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern uint GetFinalPathNameByHandle(IntPtr hFile, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(
                [MarshalAs(UnmanagedType.LPWStr)] string filename,
                [MarshalAs(UnmanagedType.U4)] uint access,
                [MarshalAs(UnmanagedType.U4)] FileShare share,
                IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
                [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
                [MarshalAs(UnmanagedType.U4)] uint flagsAndAttributes,
                IntPtr templateFile);

        public static string GetFinalPathName(string path)
        {
            var h = CreateFile(path,
                FILE_READ_EA,
                FileShare.ReadWrite | FileShare.Delete,
                IntPtr.Zero,
                FileMode.Open,
                FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);
            if (h == INVALID_HANDLE_VALUE)
                throw new Win32Exception();

            try
            {
                var sb = new StringBuilder(1024);
                var res = GetFinalPathNameByHandle(h, sb, 1024, 0);
                if (res == 0)
                    throw new Win32Exception();

                return sb.ToString();
            }
            finally
            {
                CloseHandle(h);
            }
        }

        [Flags]
        public enum RegistryAccessMask
        {
            QueryValue = 0x0001,
            SetValue = 0x0002,
            CreateSubKey = 0x0004,
            EnumerateSubKeys = 0x0008,
            Notify = 0x0010,
            CreateLink = 0x0020,
            WoW6432 = 0x0200,
            Wow6464 = 0x0100,
            Write = 0x20006,
            Read = 0x20019,
            Execute = 0x20019,
            AllAccess = 0xF003F
        }

        struct KEY_CONTROL_FLAGS_INFO_W7  // KeyFlagsInformation for Win7
        {
            ulong ControlFlags[3];
        };

        [DllImport("wdm.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr ZwQueryKey(
                UIntPtr hKey,
                uint KeyInformationClass,
                out UIntPtr KeyInformation,
                ulong Length,
                out UIntPtr ResultLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegOpenKeyEx(
           UIntPtr hKey,
           string subKey,
           int ulOptions,
           int samDesired,
           out UIntPtr hkResult);

        private const uint REG_OPTION_OPEN_LINK = 0x0008;
        private const uint KEY_CTRL_FL_W7_01__IS_VOLATILE = 0x01;
        private const uint KEY_CTRL_FL_W7_01__SYM_LINK = 0x02;

        static Dictionary<RegistryHive, UIntPtr> _hiveKeys = new Dictionary<RegistryHive, UIntPtr> {
            { RegistryHive.ClassesRoot, new UIntPtr(0x80000000u) },
            { RegistryHive.CurrentConfig, new UIntPtr(0x80000005u) },
            { RegistryHive.CurrentUser, new UIntPtr(0x80000001u) },
            //{ RegistryHive.DynData, new UIntPtr(0x80000006u) },
            { RegistryHive.LocalMachine, new UIntPtr(0x80000002u) },
            { RegistryHive.PerformanceData, new UIntPtr(0x80000004u) },
            { RegistryHive.Users, new UIntPtr(0x80000003u) } 
        };

        public static bool IsKeyLinkOrVolatile(RegistryHive Hive, string Key)
        {
            SafeRegistryHandle keyHandlePointer;
            int result = RegOpenKeyEx(_hiveKeys[Hive], Key, REG_OPTION_OPEN_LINK, RegistryAccessMask.Read, out keyHandlePointer);
            if (result == 0)
            {
                ULONG cb;
                KEY_CONTROL_FLAGS_INFO_W7 kcf;

                if (0 <= ZwQueryKey(keyHandlePointer, KeyFlagsInformation, &kcf, sizeof(kcf), &cb))
                {
                    if (kcf.ControlFlags[1] & KEY_CTRL_FL_W7_01__IS_VOLATILE)
                    {
                        Log.Debug("key is volatile\n");
                        return true;
                    }

                    if (kcf.ControlFlags[1] & KEY_CTRL_FL_W7_01__SYM_LINK)
                    {
                        Log.Debug("key is link\n");
                        return true;
                    }
                }
                RegCloseKey(hKey);
            }
            return false;
        }
    }
}