//! Stable numeric result codes. The daemon never produces user-facing text;
//! the App maps these numbers to localized strings.

/// Reason code (second field of FAIL, payload of VIOLATION).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum Code {
    DeviceUnsupported = 1,
    BootStateInvalid = 10,
    AvbKeyNotAllowed = 11,
    SelinuxNotEnforcing = 20,
    AdbEnabled = 30,
    AdbWifiEnabled = 31,
    DevSettingsEnabled = 32,
    AdbdRunning = 33,
    DeviceOwnerPresent = 40,
    ProfileOwnerPresent = 41,
    TetheringActive = 50,
    ScreenCaptureActive = 70,
    SwapNotZramOnly = 80,
    DenylistNotEnforced = 90,
    AppNotInDenylist = 91,
    InjectionFramework = 92,
    /// VoLTE is switched off for an active SIM: the App should ask the user to enable it.
    VolteOff = 100,
    ImsNotRegistered = 101,
    ImsNotOnLteNr = 102,
    ImsLinkUnresolved = 103,
    PcscfUnresolved = 104,
    ImsOnInternetApn = 105,
    ImsUidUnresolved = 106,
    CommandMissing = 110,
    CommandOutputUnparsed = 111,
    PriorValueUnencodable = 112,
    DialerNotSystem = 120,
    HomeNotSystem = 121,
    NoSystemIme = 122,
    /// This app holds the dialer role but the system phone app is not on the system image.
    SystemDialerMissing = 123,
    PeerUidRejected = 200,
    PeerPackageMismatch = 201,
    PeerSharedUid = 202,
    PeerDebuggable = 203,
    PeerApkUnreadable = 204,
    PeerSignatureMismatch = 205,
    PinnedCertMissing = 206,
    /// The package manager's signing record could not be read or parsed.
    PeerSignatureSourceMissing = 207,
    BadFrame = 210,
    UnexpectedMessage = 211,
    Busy = 212,
    LeaseMismatch = 213,
    RestorePending = 214,
    AttachTooEarly = 220,
    AttachWrongProcess = 221,
    AttachTraced = 222,
    AttachInjected = 223,
    LauncherStillAlive = 224,
    AttachInputNotCleared = 225,
    AttachTimeout = 226,
    AttachUidMismatch = 227,
    ApplyFailed = 300,
    ReadbackMismatch = 301,
    JournalWriteFailed = 302,
    PolicyInvalid = 303,
    VioFirewall = 400,
    VioSetting = 401,
    VioRadio = 402,
    VioNetType = 403,
    VioUsb = 404,
    VioInterfaceUp = 405,
    VioImsLost = 406,
    VioBearer = 407,
    VioA11y = 408,
    VioIme = 409,
    VioLeaseExpired = 410,
    VioAppGone = 411,
    RestoreIncomplete = 500,
}

impl Code {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Token used in notifications and logs, e.g. `E500`.
    pub fn token(self) -> String {
        format!("E{}", self as u16)
    }
}

/// Checklist item a failure belongs to (first field of FAIL). Numbers 1–11
/// follow the precheck list of the design (E4 step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum Item {
    Device = 0,
    Boot = 1,
    Selinux = 2,
    Adb = 3,
    Owner = 4,
    Tether = 5,
    Capture = 7,
    Swap = 8,
    Magisk = 9,
    Ims = 10,
    Commands = 11,
    Tier2 = 12,
    Auth = 20,
    Protocol = 21,
    Apply = 30,
    Attach = 31,
    Restore = 32,
    Policy = 33,
}

impl Item {
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub item: Item,
    pub code: Code,
}

impl Failure {
    pub fn new(item: Item, code: Code) -> Self {
        Self { item, code }
    }
}
