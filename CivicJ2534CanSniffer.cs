using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace CivicJ2534CanSniffer
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    internal sealed class J2534DeviceInfo
    {
        public string Name;
        public string Vendor;
        public string DllPath;
        public string RegistryPath;

        public override string ToString()
        {
            string n = string.IsNullOrEmpty(Name) ? "Unnamed J2534" : Name;
            string v = string.IsNullOrEmpty(Vendor) ? "" : " - " + Vendor;
            return n + v;
        }
    }

    internal sealed class CanFrame
    {
        public double HostSeconds;
        public uint AdapterTimestamp;
        public uint CanId;
        public bool Extended;
        public byte[] Data;
    }

    internal sealed class J2534Api : IDisposable
    {
        public const uint PROTOCOL_CAN = 5;
        public const uint PASS_FILTER = 1;
        public const uint CAN_29BIT_ID = 0x00000100;
        public const uint CAN_ID_BOTH = 0x00000800;

        // Tactrix/OpenPort 2.0 vendor-specific PassThruConnect flag.
        // Enables passive bus sniffing and prevents the OP2 from acknowledging frames.
        public const uint TACTRIX_SNIFF_MODE = 0x10000000;

        public const int STATUS_NOERROR = 0;
        public const int ERR_TIMEOUT = 0x09;
        public const int ERR_BUFFER_EMPTY = 0x10;

        private IntPtr _dll = IntPtr.Zero;
        private uint _deviceId;
        private uint _channelId;
        private uint _filterId;
        private bool _opened;
        private bool _connected;
        private bool _filterStarted;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int PassThruOpenDelegate(IntPtr pName, ref uint pDeviceId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int PassThruCloseDelegate(uint deviceId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int PassThruConnectDelegate(uint deviceId, uint protocolId, uint flags, uint baudRate, ref uint channelId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int PassThruDisconnectDelegate(uint channelId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int PassThruReadMsgsDelegate(uint channelId, IntPtr pMsg, ref uint pNumMsgs, uint timeout);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int PassThruStartMsgFilterDelegate(
            uint channelId,
            uint filterType,
            IntPtr pMaskMsg,
            IntPtr pPatternMsg,
            IntPtr pFlowControlMsg,
            ref uint pFilterId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int PassThruStopMsgFilterDelegate(uint channelId, uint filterId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        private delegate int PassThruGetLastErrorDelegate([Out] StringBuilder errorDescription);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        private delegate int PassThruReadVersionDelegate(
            uint deviceId,
            [Out] StringBuilder firmwareVersion,
            [Out] StringBuilder dllVersion,
            [Out] StringBuilder apiVersion);

        private PassThruOpenDelegate _open;
        private PassThruCloseDelegate _close;
        private PassThruConnectDelegate _connect;
        private PassThruDisconnectDelegate _disconnect;
        private PassThruReadMsgsDelegate _readMsgs;
        private PassThruStartMsgFilterDelegate _startFilter;
        private PassThruStopMsgFilterDelegate _stopFilter;
        private PassThruGetLastErrorDelegate _getLastError;
        private PassThruReadVersionDelegate _readVersion;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibraryW(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        public string DllPath { get; private set; }
        public uint DeviceId { get { return _deviceId; } }
        public uint ChannelId { get { return _channelId; } }

        public static List<J2534DeviceInfo> EnumerateInstalled()
        {
            List<J2534DeviceInfo> result = new List<J2534DeviceInfo>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            ReadRegistryView(result, seen, RegistryView.Registry32, @"SOFTWARE\PassThruSupport.04.04");
            ReadRegistryView(result, seen, RegistryView.Registry64, @"SOFTWARE\PassThruSupport.04.04");

            result.Sort(delegate(J2534DeviceInfo a, J2534DeviceInfo b)
            {
                return string.Compare(a.ToString(), b.ToString(), StringComparison.OrdinalIgnoreCase);
            });
            return result;
        }

        private static void ReadRegistryView(
            List<J2534DeviceInfo> result,
            HashSet<string> seen,
            RegistryView view,
            string rootPath)
        {
            try
            {
                using (RegistryKey hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                using (RegistryKey root = hklm.OpenSubKey(rootPath))
                {
                    if (root == null) return;

                    string[] names = root.GetSubKeyNames();
                    for (int i = 0; i < names.Length; i++)
                    {
                        using (RegistryKey dev = root.OpenSubKey(names[i]))
                        {
                            if (dev == null) continue;
                            object canObj = dev.GetValue("CAN");
                            if (canObj != null)
                            {
                                try
                                {
                                    if (Convert.ToInt32(canObj, CultureInfo.InvariantCulture) == 0)
                                        continue;
                                }
                                catch { }
                            }

                            string dll = Convert.ToString(dev.GetValue("FunctionLibrary"), CultureInfo.InvariantCulture);
                            if (string.IsNullOrWhiteSpace(dll)) continue;

                            string key = dll.Trim();
                            if (seen.Contains(key)) continue;
                            seen.Add(key);

                            J2534DeviceInfo info = new J2534DeviceInfo();
                            info.Name = Convert.ToString(dev.GetValue("Name"), CultureInfo.InvariantCulture);
                            info.Vendor = Convert.ToString(dev.GetValue("Vendor"), CultureInfo.InvariantCulture);
                            info.DllPath = key;
                            info.RegistryPath = rootPath + "\\" + names[i] + " (" + view.ToString() + ")";
                            result.Add(info);
                        }
                    }
                }
            }
            catch
            {
                // Registry discovery is convenience only; manual DLL selection remains available.
            }
        }

        public void Load(string dllPath)
        {
            if (_dll != IntPtr.Zero) throw new InvalidOperationException("A J2534 DLL is already loaded.");
            if (string.IsNullOrWhiteSpace(dllPath)) throw new ArgumentException("J2534 DLL path is empty.");
            if (!File.Exists(dllPath)) throw new FileNotFoundException("J2534 DLL not found.", dllPath);

            _dll = LoadLibraryW(dllPath);
            if (_dll == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                if (err == 193)
                    throw new InvalidOperationException(
                        "Windows error 193 while loading the J2534 DLL. This normally means DLL/app bitness mismatch. " +
                        "Try the x86 build first; use x64 only for a 64-bit J2534 DLL.");
                throw new InvalidOperationException("LoadLibrary failed. Win32 error: " + err.ToString(CultureInfo.InvariantCulture));
            }

            DllPath = dllPath;
            _open = GetFunction<PassThruOpenDelegate>("PassThruOpen");
            _close = GetFunction<PassThruCloseDelegate>("PassThruClose");
            _connect = GetFunction<PassThruConnectDelegate>("PassThruConnect");
            _disconnect = GetFunction<PassThruDisconnectDelegate>("PassThruDisconnect");
            _readMsgs = GetFunction<PassThruReadMsgsDelegate>("PassThruReadMsgs");
            _startFilter = GetFunction<PassThruStartMsgFilterDelegate>("PassThruStartMsgFilter");
            _stopFilter = GetFunction<PassThruStopMsgFilterDelegate>("PassThruStopMsgFilter");
            _getLastError = GetOptionalFunction<PassThruGetLastErrorDelegate>("PassThruGetLastError");
            _readVersion = GetOptionalFunction<PassThruReadVersionDelegate>("PassThruReadVersion");
        }

        private T GetFunction<T>(string name) where T : class
        {
            IntPtr p = GetProcAddress(_dll, name);
            if (p == IntPtr.Zero)
                throw new MissingMethodException("J2534 DLL does not export " + name + ".");
            return Marshal.GetDelegateForFunctionPointer(p, typeof(T)) as T;
        }

        private T GetOptionalFunction<T>(string name) where T : class
        {
            IntPtr p = GetProcAddress(_dll, name);
            if (p == IntPtr.Zero) return null;
            return Marshal.GetDelegateForFunctionPointer(p, typeof(T)) as T;
        }

        public string OpenAndConnect(uint baudRate, bool both11And29Bit, bool tactrixSniffMode)
        {
            if (_dll == IntPtr.Zero) throw new InvalidOperationException("Load a J2534 DLL first.");

            int rc = _open(IntPtr.Zero, ref _deviceId);
            Check(rc, "PassThruOpen");
            _opened = true;

            uint flags = both11And29Bit ? CAN_ID_BOTH : 0;
            if (tactrixSniffMode)
                flags |= TACTRIX_SNIFF_MODE;

            rc = _connect(_deviceId, PROTOCOL_CAN, flags, baudRate, ref _channelId);
            Check(rc, "PassThruConnect(CAN)");
            _connected = true;

            string version = "";
            if (_readVersion != null)
            {
                try
                {
                    StringBuilder fw = new StringBuilder(256);
                    StringBuilder dll = new StringBuilder(256);
                    StringBuilder api = new StringBuilder(256);
                    int vr = _readVersion(_deviceId, fw, dll, api);
                    if (vr == STATUS_NOERROR)
                        version = "Firmware=" + fw.ToString() + " | DLL=" + dll.ToString() + " | API=" + api.ToString();
                }
                catch { }
            }

            StartPassAllFilter();
            return version;
        }

        private void StartPassAllFilter()
        {
            int msgSize = 24 + 4128;
            IntPtr mask = Marshal.AllocHGlobal(msgSize);
            IntPtr pattern = Marshal.AllocHGlobal(msgSize);
            try
            {
                ZeroMemory(mask, msgSize);
                ZeroMemory(pattern, msgSize);

                // PASSTHRU_MSG:
                // +0 ProtocolID, +4 RxStatus, +8 TxFlags, +12 Timestamp,
                // +16 DataSize, +20 ExtraDataIndex, +24 Data[4128]
                Marshal.WriteInt32(mask, 0, (int)PROTOCOL_CAN);
                Marshal.WriteInt32(mask, 16, 4);       // 4-byte CAN identifier
                Marshal.WriteInt32(pattern, 0, (int)PROTOCOL_CAN);
                Marshal.WriteInt32(pattern, 16, 4);

                int rc = _startFilter(_channelId, PASS_FILTER, mask, pattern, IntPtr.Zero, ref _filterId);
                Check(rc, "PassThruStartMsgFilter(PASS all)");
                _filterStarted = true;
            }
            finally
            {
                Marshal.FreeHGlobal(mask);
                Marshal.FreeHGlobal(pattern);
            }
        }

        public int ReadBatch(IntPtr buffer, ref uint count, uint timeoutMs)
        {
            if (!_connected) return 8; // ERR_DEVICE_NOT_CONNECTED
            return _readMsgs(_channelId, buffer, ref count, timeoutMs);
        }

        public string DescribeError(int rc)
        {
            string name = StatusName(rc);
            if (_getLastError == null) return name;

            try
            {
                StringBuilder sb = new StringBuilder(256);
                int grc = _getLastError(sb);
                if (grc == STATUS_NOERROR && sb.Length > 0)
                    return name + ": " + sb.ToString();
            }
            catch { }
            return name;
        }

        private void Check(int rc, string operation)
        {
            if (rc == STATUS_NOERROR) return;
            throw new InvalidOperationException(operation + " failed: " + DescribeError(rc));
        }

        private static string StatusName(int rc)
        {
            switch (rc)
            {
                case 0x00: return "STATUS_NOERROR";
                case 0x01: return "ERR_NOT_SUPPORTED";
                case 0x02: return "ERR_INVALID_CHANNEL_ID";
                case 0x03: return "ERR_INVALID_PROTOCOL_ID";
                case 0x04: return "ERR_NULL_PARAMETER";
                case 0x05: return "ERR_INVALID_IOCTL_VALUE";
                case 0x06: return "ERR_INVALID_FLAGS";
                case 0x07: return "ERR_FAILED";
                case 0x08: return "ERR_DEVICE_NOT_CONNECTED";
                case 0x09: return "ERR_TIMEOUT";
                case 0x0A: return "ERR_INVALID_MSG";
                case 0x0B: return "ERR_INVALID_TIME_INTERVAL";
                case 0x0C: return "ERR_EXCEEDED_LIMIT";
                case 0x0D: return "ERR_INVALID_MSG_ID";
                case 0x0E: return "ERR_DEVICE_IN_USE";
                case 0x0F: return "ERR_INVALID_IOCTL_ID";
                case 0x10: return "ERR_BUFFER_EMPTY";
                case 0x11: return "ERR_BUFFER_FULL";
                case 0x12: return "ERR_BUFFER_OVERFLOW";
                case 0x13: return "ERR_PIN_INVALID";
                case 0x14: return "ERR_CHANNEL_IN_USE";
                case 0x15: return "ERR_MSG_PROTOCOL_ID";
                case 0x16: return "ERR_INVALID_FILTER_ID";
                case 0x17: return "ERR_NO_FLOW_CONTROL";
                case 0x18: return "ERR_NOT_UNIQUE";
                default: return "J2534 error 0x" + rc.ToString("X");
            }
        }

        private static void ZeroMemory(IntPtr ptr, int length)
        {
            byte[] zero = new byte[Math.Min(length, 4096)];
            int offset = 0;
            while (offset < length)
            {
                int n = Math.Min(zero.Length, length - offset);
                Marshal.Copy(zero, 0, IntPtr.Add(ptr, offset), n);
                offset += n;
            }
        }

        public void Dispose()
        {
            if (_filterStarted)
            {
                try { _stopFilter(_channelId, _filterId); } catch { }
                _filterStarted = false;
            }

            if (_connected)
            {
                try { _disconnect(_channelId); } catch { }
                _connected = false;
            }

            if (_opened)
            {
                try { _close(_deviceId); } catch { }
                _opened = false;
            }

            if (_dll != IntPtr.Zero)
            {
                FreeLibrary(_dll);
                _dll = IntPtr.Zero;
            }
        }
    }

    internal sealed class RowState
    {
        public DataGridViewRow Row;
        public byte[] LastData = new byte[8];
        public int LastDlc;
        public long Count;
        public double FirstTime;
        public double LastTime;
        public long[] ChangeUntilMs = new long[8];
    }

    internal sealed class BaselineFrameState
    {
        public byte[] Reference = new byte[8];
        public byte[] VolatileMask = new byte[8];
        public bool[] Seen = new bool[8];
        public int Dlc;
    }

    internal sealed class MainForm : Form
    {
        private ComboBox _deviceCombo;
        private TextBox _dllPath;
        private Button _refreshDevices;
        private Button _browseDll;
        private ComboBox _baud;
        private CheckBox _bothIds;
        private CheckBox _tactrixSniff;
        private Button _start;
        private Button _stop;
        private Button _clear;
        private Button _startLog;
        private Button _stopLog;
        private Button _markBaseline;
        private ComboBox _markerText;
        private Button _markCustom;
        private CheckBox _autoAnalyze;
        private NumericUpDown _analysisWindow;
        private Button _clearCandidates;
        private ListBox _candidateList;
        private Label _status;
        private Label _stats;
        private DataGridView _grid;
        private System.Windows.Forms.Timer _uiTimer;

        private J2534Api _api;
        private Thread _readerThread;
        private volatile bool _runReader;
        private readonly ConcurrentQueue<CanFrame> _frames = new ConcurrentQueue<CanFrame>();
        private readonly Dictionary<uint, RowState> _rows = new Dictionary<uint, RowState>();
        private readonly Stopwatch _clock = new Stopwatch();

        private readonly object _logLock = new object();
        private StreamWriter _logWriter;
        private string _logPath;

        private long _totalFrames;
        private long _uiDropped;
        private long _emptyReads;
        private long _successfulReads;
        private long _lastStatsFrames;
        private double _lastStatsTime;

        private readonly object _analysisLock = new object();
        private readonly Dictionary<uint, BaselineFrameState> _baseline = new Dictionary<uint, BaselineFrameState>();
        private readonly HashSet<string> _activeCandidateKeys = new HashSet<string>(StringComparer.Ordinal);
        private readonly ConcurrentQueue<string> _candidateUi = new ConcurrentQueue<string>();
        private bool _baselineLearning;
        private volatile bool _autoAnalyzeEnabled = true;
        private string _activeMarker = "";
        private double _activeMarkerUntil;
        private double _analysisWindowSeconds = 4.0;
        private int _activeCandidateCount;

        private const int MAX_CANDIDATES_PER_MARKER = 250;
        private const int MAX_CANDIDATE_UI = 1200;
        private const int PASSTHRU_MSG_SIZE = 24 + 4128;
        private const int READ_BATCH_SIZE = 64;
        private const uint FIRST_READ_TIMEOUT_MS = 10;
        private const uint DRAIN_READ_TIMEOUT_MS = 0;
        private const int MAX_UI_QUEUE = 25000;

        public MainForm()
        {
            Text = "Civic J2534 CAN Sniffer v2.2 Discovery";
            Width = 1180;
            Height = 720;
            MinimumSize = new Size(980, 600);
            StartPosition = FormStartPosition.CenterScreen;

            BuildUi();
            RefreshDevices();

            _uiTimer = new System.Windows.Forms.Timer();
            _uiTimer.Interval = 50;
            _uiTimer.Tick += UiTimerTick;
            _uiTimer.Start();

            FormClosing += MainFormClosing;
        }

        private void BuildUi()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.RowCount = 4;
            root.ColumnCount = 1;
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Controls.Add(root);

            TableLayoutPanel devicePanel = new TableLayoutPanel();
            devicePanel.Dock = DockStyle.Top;
            devicePanel.AutoSize = true;
            devicePanel.Padding = new Padding(8);
            devicePanel.ColumnCount = 6;
            devicePanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            devicePanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 45F));
            devicePanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            devicePanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 55F));
            devicePanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            devicePanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            devicePanel.Controls.Add(new Label { Text = "J2534 device:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
            _deviceCombo = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
            _deviceCombo.SelectedIndexChanged += DeviceSelected;
            devicePanel.Controls.Add(_deviceCombo, 1, 0);

            _refreshDevices = new Button { Text = "Refresh", AutoSize = true };
            _refreshDevices.Click += delegate { RefreshDevices(); };
            devicePanel.Controls.Add(_refreshDevices, 2, 0);

            _dllPath = new TextBox { Dock = DockStyle.Fill };
            devicePanel.Controls.Add(_dllPath, 3, 0);

            _browseDll = new Button { Text = "Browse DLL...", AutoSize = true };
            _browseDll.Click += BrowseDll;
            devicePanel.Controls.Add(_browseDll, 4, 0);

            _baud = new ComboBox { Width = 110, DropDownStyle = ComboBoxStyle.DropDownList };
            _baud.Items.AddRange(new object[] { "500000", "250000", "125000", "100000", "83333", "50000", "33333" });
            _baud.SelectedIndex = 0;
            devicePanel.Controls.Add(_baud, 5, 0);

            _bothIds = new CheckBox
            {
                Text = "11 + 29-bit IDs",
                AutoSize = true,
                Checked = false,
                Anchor = AnchorStyles.Left
            };
            devicePanel.Controls.Add(_bothIds, 5, 1);

            _tactrixSniff = new CheckBox
            {
                Text = "OpenPort SNIFF_MODE",
                AutoSize = true,
                Checked = false,
                Anchor = AnchorStyles.Left
            };
            devicePanel.Controls.Add(_tactrixSniff, 5, 2);

            Label hint = new Label
            {
                Text = "Civic default: F-CAN 500 kbit/s on OBD 6/14. 33.333k is available for body-bus experiments only if your adapter/wiring actually reaches B-CAN. App never transmits.",
                AutoSize = true,
                ForeColor = Color.DimGray,
                Dock = DockStyle.Fill
            };
            devicePanel.Controls.Add(hint, 0, 1);
            devicePanel.SetColumnSpan(hint, 5);

            Label sniffHint = new Label
            {
                Text = "OpenPort DLLs are auto-detected and SNIFF_MODE is enabled automatically.",
                AutoSize = true,
                ForeColor = Color.DimGray,
                Dock = DockStyle.Fill
            };
            devicePanel.Controls.Add(sniffHint, 0, 2);
            devicePanel.SetColumnSpan(sniffHint, 5);

            root.Controls.Add(devicePanel, 0, 0);

            FlowLayoutPanel controls = new FlowLayoutPanel();
            controls.Dock = DockStyle.Top;
            controls.AutoSize = true;
            controls.Padding = new Padding(8, 0, 8, 6);

            _start = new Button { Text = "Start Capture", AutoSize = true };
            _start.Click += StartCapture;
            controls.Controls.Add(_start);

            _stop = new Button { Text = "Stop", AutoSize = true, Enabled = false };
            _stop.Click += delegate { StopCapture(); };
            controls.Controls.Add(_stop);

            _clear = new Button { Text = "Clear Grid", AutoSize = true };
            _clear.Click += delegate { ClearGrid(); };
            controls.Controls.Add(_clear);

            controls.Controls.Add(new Label { Text = "     Log:", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });

            _startLog = new Button { Text = "Start CSV Log...", AutoSize = true };
            _startLog.Click += StartLog;
            controls.Controls.Add(_startLog);

            _stopLog = new Button { Text = "Stop Log", AutoSize = true, Enabled = false };
            _stopLog.Click += delegate { StopLog(); };
            controls.Controls.Add(_stopLog);

            controls.Controls.Add(new Label { Text = "     Mark experiment:", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });

            _markBaseline = new Button { Text = "BASELINE", AutoSize = true };
            _markBaseline.Click += delegate { WriteMarker("BASELINE"); };
            controls.Controls.Add(_markBaseline);

            controls.Controls.Add(new Label { Text = "Custom marker:", AutoSize = true, Padding = new Padding(6, 6, 0, 0) });

            _markerText = new ComboBox
            {
                Width = 190,
                DropDownStyle = ComboBoxStyle.DropDown
            };
            _markerText.Items.AddRange(new object[]
            {
                // Confirmed / high-value Civic functions
                "VSA_OFF", "VSA_ON", "DIM_RIGHT", "DIM_LEFT",
                "BRAKE_PRESS", "BRAKE_RELEASE", "CLUTCH_PRESS", "CLUTCH_RELEASE",
                "CRUISE_MAIN_ON", "CRUISE_MAIN_OFF", "CRUISE_SET_PRESS", "CRUISE_SET_RELEASE",
                "CRUISE_RES_PRESS", "CRUISE_RES_RELEASE", "CRUISE_CANCEL_PRESS", "CRUISE_CANCEL_RELEASE",

                // Exterior lighting / stalks
                "HEADLIGHT_OFF", "PARK_LIGHT_ON", "LOW_BEAM_ON", "HIGH_BEAM_ON", "HIGH_BEAM_FLASH",
                "TURN_LEFT_ON", "TURN_LEFT_OFF", "TURN_RIGHT_ON", "TURN_RIGHT_OFF", "HAZARD_ON", "HAZARD_OFF",
                "FOG_FRONT_ON", "FOG_FRONT_OFF", "FOG_REAR_ON", "FOG_REAR_OFF",

                // Wipers / washer
                "WIPER_MIST", "WIPER_OFF", "WIPER_INT", "WIPER_LOW", "WIPER_HIGH", "WASHER_FRONT",

                // Body / doors
                "HORN_PRESS", "HORN_RELEASE", "HANDBRAKE_ON", "HANDBRAKE_OFF", "REVERSE_IN", "REVERSE_OUT",
                "DRIVER_DOOR_OPEN", "DRIVER_DOOR_CLOSE", "PASS_DOOR_OPEN", "PASS_DOOR_CLOSE",
                "LOCK", "UNLOCK", "TRUNK_OPEN",
                "WINDOW_DOWN_LEFT", "WINDOW_UP_LEFT", "WINDOW_DOWN_RIGHT", "WINDOW_UP_RIGHT",

                // HVAC / convenience
                "AC_ON", "AC_OFF", "AC_TEMP_UP", "AC_TEMP_DOWN", "FAN_UP", "FAN_DOWN",
                "RECIRC_ON", "RECIRC_OFF", "REAR_DEFROST_ON", "REAR_DEFROST_OFF",

                // Steering wheel / audio
                "STEER_VOL_UP", "STEER_VOL_DOWN", "STEER_CH_UP", "STEER_CH_DOWN",
                "STEER_MODE", "STEER_MUTE", "PLAYER_DISP", "PLAYER_CLOCK", "PLAYER_TAPTY", "PLAYER_ASEL",

                // Drivetrain / sensor experiments
                "THROTTLE_IDLE", "THROTTLE_25", "THROTTLE_50", "THROTTLE_BLIP",
                "STEERING_CENTER", "STEERING_LEFT", "STEERING_RIGHT",
                "ENGINE_START", "ENGINE_STOP"
            });
            _markerText.KeyDown += MarkerTextKeyDown;
            controls.Controls.Add(_markerText);

            _markCustom = new Button { Text = "MARK", AutoSize = true };
            _markCustom.Click += delegate { WriteCustomMarker(); };
            controls.Controls.Add(_markCustom);

            controls.Controls.Add(new Label { Text = "     Discovery:", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });

            _autoAnalyze = new CheckBox
            {
                Text = "Auto candidates",
                AutoSize = true,
                Checked = true,
                Padding = new Padding(0, 3, 0, 0)
            };
            _autoAnalyze.CheckedChanged += delegate { _autoAnalyzeEnabled = _autoAnalyze.Checked; };
            controls.Controls.Add(_autoAnalyze);

            controls.Controls.Add(new Label { Text = "Window s:", AutoSize = true, Padding = new Padding(4, 6, 0, 0) });
            _analysisWindow = new NumericUpDown
            {
                Width = 55,
                DecimalPlaces = 1,
                Increment = 0.5M,
                Minimum = 1.0M,
                Maximum = 15.0M,
                Value = 4.0M
            };
            _analysisWindow.ValueChanged += delegate { _analysisWindowSeconds = (double)_analysisWindow.Value; };
            controls.Controls.Add(_analysisWindow);

            _clearCandidates = new Button { Text = "Clear Candidates", AutoSize = true };
            _clearCandidates.Click += delegate { ClearCandidates(); };
            controls.Controls.Add(_clearCandidates);

            root.Controls.Add(controls, 0, 1);

            _grid = new DataGridView();
            _grid.Dock = DockStyle.Fill;
            _grid.AllowUserToAddRows = false;
            _grid.AllowUserToDeleteRows = false;
            _grid.ReadOnly = true;
            _grid.RowHeadersVisible = false;
            _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            _grid.MultiSelect = false;
            _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None;
            _grid.BackgroundColor = SystemColors.Window;
            _grid.Font = new Font(FontFamily.GenericMonospace, 9F);

            AddColumn("ID", "CAN ID", 80);
            AddColumn("DLC", "DLC", 45);
            for (int i = 0; i < 8; i++) AddColumn("B" + i.ToString(), "B" + i.ToString(), 45);
            AddColumn("Count", "Count", 90);
            AddColumn("Hz", "Hz", 70);
            AddColumn("Age", "Age ms", 80);
            AddColumn("Ext", "Ext", 45);

            SplitContainer captureSplit = new SplitContainer();
            captureSplit.Dock = DockStyle.Fill;
            captureSplit.Orientation = Orientation.Horizontal;
            captureSplit.SplitterDistance = 390;
            captureSplit.Panel1.Controls.Add(_grid);

            TableLayoutPanel candidatePanel = new TableLayoutPanel();
            candidatePanel.Dock = DockStyle.Fill;
            candidatePanel.RowCount = 2;
            candidatePanel.ColumnCount = 1;
            candidatePanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            candidatePanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            candidatePanel.Controls.Add(new Label
            {
                Text = "Discovery candidates — byte/bit changes not seen during BASELINE",
                AutoSize = true,
                Padding = new Padding(3, 3, 3, 3)
            }, 0, 0);
            _candidateList = new ListBox();
            _candidateList.Dock = DockStyle.Fill;
            _candidateList.Font = new Font(FontFamily.GenericMonospace, 8.5F);
            candidatePanel.Controls.Add(_candidateList, 0, 1);
            captureSplit.Panel2.Controls.Add(candidatePanel);

            root.Controls.Add(captureSplit, 0, 2);

            FlowLayoutPanel footer = new FlowLayoutPanel();
            footer.Dock = DockStyle.Fill;
            footer.AutoSize = true;
            footer.Padding = new Padding(8, 4, 8, 6);

            _status = new Label { Text = "Disconnected", AutoSize = true, Padding = new Padding(0, 3, 15, 0) };
            _stats = new Label { Text = "Frames: 0", AutoSize = true, Padding = new Padding(0, 3, 0, 0) };
            footer.Controls.Add(_status);
            footer.Controls.Add(_stats);
            root.Controls.Add(footer, 0, 3);
        }

        private void AddColumn(string name, string header, int width)
        {
            DataGridViewTextBoxColumn c = new DataGridViewTextBoxColumn();
            c.Name = name;
            c.HeaderText = header;
            c.Width = width;
            c.SortMode = DataGridViewColumnSortMode.Automatic;
            _grid.Columns.Add(c);
        }

        private void RefreshDevices()
        {
            string previous = _dllPath == null ? "" : _dllPath.Text;
            List<J2534DeviceInfo> devices = J2534Api.EnumerateInstalled();

            _deviceCombo.Items.Clear();
            for (int i = 0; i < devices.Count; i++) _deviceCombo.Items.Add(devices[i]);

            if (_deviceCombo.Items.Count > 0)
            {
                _deviceCombo.SelectedIndex = 0;
            }
            else
            {
                _dllPath.Text = previous;
                _status.Text = "No J2534 04.04 CAN driver found in registry. Use Browse DLL.";
            }
        }

        private void DeviceSelected(object sender, EventArgs e)
        {
            J2534DeviceInfo info = _deviceCombo.SelectedItem as J2534DeviceInfo;
            if (info != null)
            {
                _dllPath.Text = info.DllPath;
                AutoSelectSniffMode(info.DllPath);
                _status.Text = "Selected: " + info.ToString();
            }
        }

        private void AutoSelectSniffMode(string dllPath)
        {
            if (_tactrixSniff == null) return;

            string name = "";
            try { name = Path.GetFileName(dllPath ?? ""); } catch { }

            bool looksLikeOpenPort =
                name.IndexOf("op20pt", StringComparison.OrdinalIgnoreCase) >= 0 ||
                name.IndexOf("openport", StringComparison.OrdinalIgnoreCase) >= 0;

            _tactrixSniff.Checked = looksLikeOpenPort;
        }

        private void BrowseDll(object sender, EventArgs e)
        {
            using (OpenFileDialog d = new OpenFileDialog())
            {
                d.Title = "Select J2534 PassThru DLL";
                d.Filter = "DLL files (*.dll)|*.dll|All files (*.*)|*.*";
                if (d.ShowDialog(this) == DialogResult.OK)
                {
                    _dllPath.Text = d.FileName;
                    _deviceCombo.SelectedIndex = -1;
                    AutoSelectSniffMode(d.FileName);
                }
            }
        }

        private void StartCapture(object sender, EventArgs e)
        {
            if (_readerThread != null) return;

            uint baud;
            if (!uint.TryParse(Convert.ToString(_baud.SelectedItem, CultureInfo.InvariantCulture), out baud))
            {
                MessageBox.Show(this, "Invalid baud rate.", "Civic CAN Sniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                ClearGrid();

                _api = new J2534Api();
                _api.Load(_dllPath.Text.Trim());
                bool useTactrixSniff = _tactrixSniff.Checked;
                string version = _api.OpenAndConnect(baud, _bothIds.Checked, useTactrixSniff);

                _clock.Reset();
                _clock.Start();
                _totalFrames = 0;
                _uiDropped = 0;
                _emptyReads = 0;
                _successfulReads = 0;
                _lastStatsFrames = 0;
                _lastStatsTime = 0;
                ClearCandidates();

                _runReader = true;
                _readerThread = new Thread(ReaderLoop);
                _readerThread.IsBackground = true;
                _readerThread.Name = "J2534 CAN Reader";
                _readerThread.Start();

                _start.Enabled = false;
                _stop.Enabled = true;
                _deviceCombo.Enabled = false;
                _refreshDevices.Enabled = false;
                _browseDll.Enabled = false;
                _dllPath.Enabled = false;
                _baud.Enabled = false;
                _bothIds.Enabled = false;
                _tactrixSniff.Enabled = false;

                _status.Text =
                    "CAPTURING CAN @ " + baud.ToString(CultureInfo.InvariantCulture) + " bit/s" +
                    (useTactrixSniff ? " | OpenPort SNIFF_MODE" : "");
                if (!string.IsNullOrEmpty(version)) _status.Text += " | " + version;
            }
            catch (Exception ex)
            {
                if (_api != null)
                {
                    _api.Dispose();
                    _api = null;
                }
                MessageBox.Show(this, ex.Message, "J2534 connection failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                _status.Text = "Connection failed";
            }
        }

        private void ReaderLoop()
        {
            // Low-latency strategy:
            //   1) Ask for exactly one message with a short timeout. This lets the UI
            //      react as soon as the first frame arrives instead of waiting for a
            //      large J2534 batch to fill.
            //   2) Once one frame is received, drain all already-buffered frames in
            //      larger non-blocking batches.
            IntPtr buffer = Marshal.AllocHGlobal(PASSTHRU_MSG_SIZE * READ_BATCH_SIZE);
            try
            {
                while (_runReader)
                {
                    uint count = 1;
                    int rc;

                    try
                    {
                        rc = _api.ReadBatch(buffer, ref count, FIRST_READ_TIMEOUT_MS);
                    }
                    catch
                    {
                        break;
                    }

                    if (rc != J2534Api.STATUS_NOERROR)
                    {
                        if (rc == J2534Api.ERR_BUFFER_EMPTY || rc == J2534Api.ERR_TIMEOUT)
                        {
                            Interlocked.Increment(ref _emptyReads);
                            continue;
                        }

                        string err = _api.DescribeError(rc);
                        BeginInvoke((MethodInvoker)delegate
                        {
                            _status.Text = "Read error: " + err;
                        });
                        Thread.Sleep(25);
                        continue;
                    }

                    if (count > 0)
                    {
                        Interlocked.Increment(ref _successfulReads);
                        ProcessReadBatch(buffer, count);
                    }

                    // Drain anything the adapter already has queued without waiting.
                    while (_runReader)
                    {
                        count = READ_BATCH_SIZE;
                        try
                        {
                            rc = _api.ReadBatch(buffer, ref count, DRAIN_READ_TIMEOUT_MS);
                        }
                        catch
                        {
                            _runReader = false;
                            break;
                        }

                        if (rc == J2534Api.STATUS_NOERROR)
                        {
                            if (count == 0)
                                break;

                            ProcessReadBatch(buffer, count);

                            // If the returned batch is smaller than requested, the
                            // driver's receive queue is probably drained.
                            if (count < READ_BATCH_SIZE)
                                break;

                            continue;
                        }

                        if (rc == J2534Api.ERR_BUFFER_EMPTY || rc == J2534Api.ERR_TIMEOUT)
                            break;

                        string err = _api.DescribeError(rc);
                        BeginInvoke((MethodInvoker)delegate
                        {
                            _status.Text = "Read error: " + err;
                        });
                        break;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private void ProcessReadBatch(IntPtr buffer, uint count)
        {
            for (uint i = 0; i < count; i++)
            {
                IntPtr p = IntPtr.Add(buffer, checked((int)i * PASSTHRU_MSG_SIZE));
                CanFrame f = ParseFrame(p);
                if (f == null) continue;

                Interlocked.Increment(ref _totalFrames);

                if (_frames.Count < MAX_UI_QUEUE)
                    _frames.Enqueue(f);
                else
                    Interlocked.Increment(ref _uiDropped);

                AnalyzeFrame(f);
                WriteFrameToLog(f);
            }
        }

        private CanFrame ParseFrame(IntPtr p)
        {
            uint protocol = unchecked((uint)Marshal.ReadInt32(p, 0));
            uint rxStatus = unchecked((uint)Marshal.ReadInt32(p, 4));
            uint timestamp = unchecked((uint)Marshal.ReadInt32(p, 12));
            uint dataSize = unchecked((uint)Marshal.ReadInt32(p, 16));

            if (protocol != J2534Api.PROTOCOL_CAN) return null;
            if (dataSize < 4 || dataSize > 12) return null;

            byte[] raw = new byte[dataSize];
            Marshal.Copy(IntPtr.Add(p, 24), raw, 0, raw.Length);

            uint id =
                ((uint)raw[0] << 24) |
                ((uint)raw[1] << 16) |
                ((uint)raw[2] << 8) |
                raw[3];

            int dlc = raw.Length - 4;
            if (dlc > 8) dlc = 8;

            byte[] data = new byte[dlc];
            if (dlc > 0) Array.Copy(raw, 4, data, 0, dlc);

            CanFrame f = new CanFrame();
            f.HostSeconds = _clock.Elapsed.TotalSeconds;
            f.AdapterTimestamp = timestamp;
            f.CanId = id;
            f.Extended = id > 0x7FF || (rxStatus & J2534Api.CAN_29BIT_ID) != 0;
            f.Data = data;
            return f;
        }

        private void UiTimerTick(object sender, EventArgs e)
        {
            int processed = 0;
            CanFrame f;
            while (processed < 5000 && _frames.TryDequeue(out f))
            {
                UpdateRow(f);
                processed++;
            }

            if (_candidateList != null)
            {
                string candidate;
                int candidateProcessed = 0;
                while (candidateProcessed < 200 && _candidateUi.TryDequeue(out candidate))
                {
                    _candidateList.Items.Add(candidate);
                    while (_candidateList.Items.Count > MAX_CANDIDATE_UI)
                        _candidateList.Items.RemoveAt(0);
                    candidateProcessed++;
                }
                if (candidateProcessed > 0 && _candidateList.Items.Count > 0)
                    _candidateList.TopIndex = _candidateList.Items.Count - 1;
            }

            long nowMs = _clock.IsRunning ? _clock.ElapsedMilliseconds : 0;
            foreach (KeyValuePair<uint, RowState> kv in _rows)
            {
                RowState s = kv.Value;
                for (int i = 0; i < 8; i++)
                {
                    if (s.ChangeUntilMs[i] != 0 && nowMs >= s.ChangeUntilMs[i])
                    {
                        s.Row.Cells["B" + i.ToString()].Style.BackColor = Color.White;
                        s.ChangeUntilMs[i] = 0;
                    }
                }

                if (_clock.IsRunning)
                {
                    double ageMs = Math.Max(0.0, (_clock.Elapsed.TotalSeconds - s.LastTime) * 1000.0);
                    s.Row.Cells["Age"].Value = ageMs.ToString("0", CultureInfo.InvariantCulture);
                }
            }

            double now = _clock.IsRunning ? _clock.Elapsed.TotalSeconds : 0;
            if (now - _lastStatsTime >= 0.5)
            {
                long total = Interlocked.Read(ref _totalFrames);
                double dt = now - _lastStatsTime;
                double fps = dt > 0 ? (total - _lastStatsFrames) / dt : 0;
                _stats.Text =
                    "Frames: " + total.ToString("N0", CultureInfo.InvariantCulture) +
                    "   IDs: " + _rows.Count.ToString(CultureInfo.InvariantCulture) +
                    "   Rate: " + fps.ToString("0", CultureInfo.InvariantCulture) + "/s" +
                    "   Reads: " + Interlocked.Read(ref _successfulReads).ToString("N0", CultureInfo.InvariantCulture) +
                    "   Empty: " + Interlocked.Read(ref _emptyReads).ToString("N0", CultureInfo.InvariantCulture) +
                    "   UI dropped: " + Interlocked.Read(ref _uiDropped).ToString("N0", CultureInfo.InvariantCulture) +
                    (string.IsNullOrEmpty(_logPath) ? "" : "   Logging: " + Path.GetFileName(_logPath));

                _lastStatsFrames = total;
                _lastStatsTime = now;
            }
        }

        private void UpdateRow(CanFrame f)
        {
            RowState s;
            if (!_rows.TryGetValue(f.CanId, out s))
            {
                int index = _grid.Rows.Add();
                DataGridViewRow row = _grid.Rows[index];
                s = new RowState();
                s.Row = row;
                s.FirstTime = f.HostSeconds;
                s.LastTime = f.HostSeconds;
                _rows[f.CanId] = s;

                row.Cells["ID"].Value = f.CanId.ToString(f.Extended ? "X8" : "X3");
                row.Cells["Ext"].Value = f.Extended ? "Y" : "";
                for (int i = 0; i < 8; i++)
                {
                    row.Cells["B" + i.ToString()].Value = "--";
                    row.Cells["B" + i.ToString()].Style.BackColor = Color.White;
                }
            }

            s.Count++;
            s.LastTime = f.HostSeconds;
            int dlc = f.Data.Length;
            s.Row.Cells["DLC"].Value = dlc.ToString(CultureInfo.InvariantCulture);

            long nowMs = _clock.ElapsedMilliseconds;
            for (int i = 0; i < 8; i++)
            {
                DataGridViewCell cell = s.Row.Cells["B" + i.ToString()];
                if (i < dlc)
                {
                    byte b = f.Data[i];
                    bool changed = s.Count > 1 && (i >= s.LastDlc || s.LastData[i] != b);
                    cell.Value = b.ToString("X2");

                    if (changed)
                    {
                        cell.Style.BackColor = Color.Gold;
                        s.ChangeUntilMs[i] = nowMs + 700;
                    }
                    s.LastData[i] = b;
                }
                else
                {
                    cell.Value = "--";
                    s.LastData[i] = 0;
                }
            }

            s.LastDlc = dlc;
            s.Row.Cells["Count"].Value = s.Count.ToString("N0", CultureInfo.InvariantCulture);

            double duration = s.LastTime - s.FirstTime;
            double hz = duration > 0.05 ? (s.Count - 1) / duration : 0;
            s.Row.Cells["Hz"].Value = hz.ToString("0.0", CultureInfo.InvariantCulture);
            s.Row.Cells["Age"].Value = "0";
        }

        private void ClearGrid()
        {
            CanFrame throwAway;
            while (_frames.TryDequeue(out throwAway)) { }
            _rows.Clear();
            _grid.Rows.Clear();
            lock (_analysisLock)
            {
                _baseline.Clear();
                _baselineLearning = false;
                _activeMarker = "";
                _activeMarkerUntil = 0;
                _activeCandidateKeys.Clear();
                _activeCandidateCount = 0;
            }
        }

        private void ClearCandidates()
        {
            string ignored;
            while (_candidateUi.TryDequeue(out ignored)) { }
            if (_candidateList != null) _candidateList.Items.Clear();
        }

        private void StartLog(object sender, EventArgs e)
        {
            if (_logWriter != null) return;

            using (SaveFileDialog d = new SaveFileDialog())
            {
                d.Title = "Save Civic CAN capture";
                d.Filter = "CSV log (*.csv)|*.csv|All files (*.*)|*.*";
                d.FileName = "civic_canmap_" + DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture) + ".csv";

                if (d.ShowDialog(this) != DialogResult.OK) return;

                lock (_logLock)
                {
                    _logWriter = new StreamWriter(d.FileName, false, new UTF8Encoding(false), 1024 * 64);
                    _logWriter.AutoFlush = false;
                    _logPath = d.FileName;
                    _logWriter.WriteLine("# Civic J2534 CAN Sniffer v2.2 Discovery");
                    _logWriter.WriteLine("# Created," + DateTime.Now.ToString("O", CultureInfo.InvariantCulture));
                    _logWriter.WriteLine("# DLL," + Csv(_dllPath.Text));
                    _logWriter.WriteLine("# Baud," + Convert.ToString(_baud.SelectedItem, CultureInfo.InvariantCulture));
                    _logWriter.WriteLine("# TactrixSniffMode," + (_tactrixSniff.Checked ? "1" : "0"));
                    _logWriter.WriteLine("# AutoCandidates," + (_autoAnalyzeEnabled ? "1" : "0"));
                    _logWriter.WriteLine("# CandidateWindowSeconds," + _analysisWindowSeconds.ToString("0.0", CultureInfo.InvariantCulture));
                    _logWriter.WriteLine("# Press BASELINE or enter any custom marker immediately before each experiment phase.");
                    _logWriter.WriteLine("HostSeconds,AdapterTimestampUs,CanId,Extended,DLC,Data");
                    _logWriter.Flush();
                }

                _startLog.Enabled = false;
                _stopLog.Enabled = true;
            }
        }

        private void StopLog()
        {
            lock (_logLock)
            {
                if (_logWriter != null)
                {
                    try { _logWriter.Flush(); } catch { }
                    try { _logWriter.Dispose(); } catch { }
                    _logWriter = null;
                }
                _logPath = null;
            }
            _startLog.Enabled = true;
            _stopLog.Enabled = false;
        }

        private void MarkerTextKeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                WriteCustomMarker();
                e.SuppressKeyPress = true;
                e.Handled = true;
            }
        }

        private void WriteCustomMarker()
        {
            if (_markerText == null) return;

            string marker = _markerText.Text == null ? "" : _markerText.Text.Trim();
            if (marker.Length == 0)
            {
                MessageBox.Show(
                    this,
                    "Enter or select a custom marker first.",
                    "Experiment marker",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                _markerText.Focus();
                return;
            }

            WriteMarker(marker);

            // Keep recently used custom entries available in the drop-down.
            bool exists = false;
            for (int i = 0; i < _markerText.Items.Count; i++)
            {
                if (string.Equals(
                    Convert.ToString(_markerText.Items[i], CultureInfo.InvariantCulture),
                    marker,
                    StringComparison.OrdinalIgnoreCase))
                {
                    exists = true;
                    break;
                }
            }

            if (!exists)
                _markerText.Items.Insert(0, marker);

            _markerText.SelectAll();
            _markerText.Focus();
        }

        private void WriteMarker(string marker)
        {
            // Check logging first, but never hold _logLock while taking _analysisLock.
            // The reader's candidate path takes _analysisLock then _logLock.
            lock (_logLock)
            {
                if (_logWriter == null)
                {
                    MessageBox.Show(this, "Start a CSV log first.", "Experiment marker", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
            }

            string cleanMarker = marker == null ? "" : marker.Replace("\r", " ").Replace("\n", " ").Trim();
            if (cleanMarker.Length == 0)
                cleanMarker = "MARK";

            double t = _clock.IsRunning ? _clock.Elapsed.TotalSeconds : 0.0;

            lock (_analysisLock)
            {
                if (string.Equals(cleanMarker, "BASELINE", StringComparison.OrdinalIgnoreCase))
                {
                    _baseline.Clear();
                    _baselineLearning = true;
                    _activeMarker = "";
                    _activeMarkerUntil = 0;
                    _activeCandidateKeys.Clear();
                    _activeCandidateCount = 0;
                }
                else if (_autoAnalyzeEnabled)
                {
                    _baselineLearning = false;
                    _activeMarker = cleanMarker;
                    _activeMarkerUntil = t + _analysisWindowSeconds;
                    _activeCandidateKeys.Clear();
                    _activeCandidateCount = 0;
                }
            }

            lock (_logLock)
            {
                if (_logWriter == null) return;
                _logWriter.WriteLine(
                    "# MARK," +
                    t.ToString("0.000000", CultureInfo.InvariantCulture) +
                    "," + Csv(cleanMarker) +
                    "," + DateTime.Now.ToString("O", CultureInfo.InvariantCulture));
                _logWriter.Flush();
            }

            _status.Text = string.Equals(cleanMarker, "BASELINE", StringComparison.OrdinalIgnoreCase)
                ? "BASELINE learning active — leave controls untouched, then mark an action"
                : "Marker written: " + cleanMarker + (_autoAnalyzeEnabled ? " | candidate window " + _analysisWindowSeconds.ToString("0.0", CultureInfo.InvariantCulture) + " s" : "");
        }

        private void AnalyzeFrame(CanFrame f)
        {
            lock (_analysisLock)
            {
                if (_baselineLearning)
                {
                    BaselineFrameState bs;
                    if (!_baseline.TryGetValue(f.CanId, out bs))
                    {
                        bs = new BaselineFrameState();
                        _baseline[f.CanId] = bs;
                    }

                    bs.Dlc = Math.Max(bs.Dlc, f.Data.Length);
                    int n = Math.Min(8, f.Data.Length);
                    for (int i = 0; i < n; i++)
                    {
                        byte b = f.Data[i];
                        if (!bs.Seen[i])
                        {
                            bs.Reference[i] = b;
                            bs.Seen[i] = true;
                        }
                        else
                        {
                            bs.VolatileMask[i] |= (byte)(bs.Reference[i] ^ b);
                            bs.Reference[i] = b;
                        }
                    }
                    return;
                }

                if (!_autoAnalyzeEnabled || string.IsNullOrEmpty(_activeMarker)) return;
                if (f.HostSeconds > _activeMarkerUntil)
                {
                    _activeMarker = "";
                    return;
                }
                if (_activeCandidateCount >= MAX_CANDIDATES_PER_MARKER) return;

                BaselineFrameState baseline;
                if (!_baseline.TryGetValue(f.CanId, out baseline))
                {
                    string newIdKey = "NEWID:" + f.CanId.ToString("X8", CultureInfo.InvariantCulture);
                    if (_activeCandidateKeys.Add(newIdKey))
                    {
                        string text = FormatCandidate(f, -1, 0, 0, 0, "NEW_ID_AFTER_MARKER");
                        EmitCandidate(text, f, -1, 0, 0, 0, "NEW_ID_AFTER_MARKER");
                    }
                    return;
                }

                int bytes = Math.Min(8, f.Data.Length);
                for (int i = 0; i < bytes; i++)
                {
                    if (!baseline.Seen[i]) continue;

                    byte oldValue = baseline.Reference[i];
                    byte newValue = f.Data[i];
                    byte changedMask = (byte)(oldValue ^ newValue);
                    if (changedMask == 0) continue;

                    // Bits that moved during BASELINE are treated as normal bus noise/counters.
                    // StableChanged therefore prioritizes control-state transitions.
                    byte stableChanged = (byte)(changedMask & ~baseline.VolatileMask[i]);

                    // For a byte that was completely stable during baseline, keep the full delta.
                    // This also catches stepped/analog controls such as the Civic dimmer byte.
                    if (stableChanged == 0 && baseline.VolatileMask[i] != 0)
                        continue;

                    string key = f.CanId.ToString("X8", CultureInfo.InvariantCulture) + ":" +
                                 i.ToString(CultureInfo.InvariantCulture) + ":" +
                                 newValue.ToString("X2", CultureInfo.InvariantCulture) + ":" +
                                 stableChanged.ToString("X2", CultureInfo.InvariantCulture);
                    if (!_activeCandidateKeys.Add(key)) continue;

                    string hint = KnownSignalHint(f.CanId, i, stableChanged, newValue);
                    string line = FormatCandidate(f, i, oldValue, newValue, stableChanged, hint);
                    EmitCandidate(line, f, i, oldValue, newValue, stableChanged, hint);

                    if (_activeCandidateCount >= MAX_CANDIDATES_PER_MARKER)
                        break;
                }
            }
        }

        private string FormatCandidate(CanFrame f, int byteIndex, byte oldValue, byte newValue, byte changedMask, string hint)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(f.HostSeconds.ToString("0.000000", CultureInfo.InvariantCulture));
            sb.Append("  ");
            sb.Append(_activeMarker.PadRight(Math.Min(24, Math.Max(1, _activeMarker.Length))));
            sb.Append("  ID 0x");
            sb.Append(f.CanId.ToString(f.Extended ? "X8" : "X3", CultureInfo.InvariantCulture));

            if (byteIndex >= 0)
            {
                sb.Append("  B");
                sb.Append(byteIndex.ToString(CultureInfo.InvariantCulture));
                sb.Append(" ");
                sb.Append(oldValue.ToString("X2", CultureInfo.InvariantCulture));
                sb.Append("->");
                sb.Append(newValue.ToString("X2", CultureInfo.InvariantCulture));
                sb.Append("  bits=");
                sb.Append(changedMask.ToString("X2", CultureInfo.InvariantCulture));
            }

            if (!string.IsNullOrEmpty(hint))
            {
                sb.Append("  ");
                sb.Append(hint);
            }
            return sb.ToString();
        }

        private void EmitCandidate(string display, CanFrame f, int byteIndex, byte oldValue, byte newValue, byte changedMask, string hint)
        {
            _activeCandidateCount++;
            _candidateUi.Enqueue(display);

            lock (_logLock)
            {
                if (_logWriter == null) return;
                _logWriter.WriteLine(
                    "# CANDIDATE," +
                    f.HostSeconds.ToString("0.000000", CultureInfo.InvariantCulture) + "," +
                    Csv(_activeMarker) + "," +
                    f.CanId.ToString(f.Extended ? "X8" : "X3", CultureInfo.InvariantCulture) + "," +
                    (byteIndex < 0 ? "NEW_ID" : "B" + byteIndex.ToString(CultureInfo.InvariantCulture)) + "," +
                    (byteIndex < 0 ? "" : oldValue.ToString("X2", CultureInfo.InvariantCulture)) + "," +
                    (byteIndex < 0 ? "" : newValue.ToString("X2", CultureInfo.InvariantCulture)) + "," +
                    (byteIndex < 0 ? "" : changedMask.ToString("X2", CultureInfo.InvariantCulture)) + "," +
                    Csv(hint));
            }
        }

        private static string KnownSignalHint(uint id, int byteIndex, byte changedMask, byte newValue)
        {
            if (id == 0x164 && byteIndex == 0)
            {
                List<string> hints = new List<string>();
                if ((changedMask & 0x10) != 0)
                    hints.Add((newValue & 0x10) != 0 ? "KNOWN:VSA_BUTTON=PRESS" : "KNOWN:VSA_BUTTON=RELEASE");
                if ((changedMask & 0x01) != 0)
                    hints.Add((newValue & 0x01) != 0 ? "KNOWN:ILLUMINATION=ON" : "KNOWN:ILLUMINATION=OFF");
                return string.Join(" | ", hints.ToArray());
            }

            if (id == 0x1A4 && byteIndex == 3 && (changedMask & 0x10) != 0)
                return (newValue & 0x10) != 0 ? "KNOWN:VSA_DISABLED=YES" : "KNOWN:VSA_DISABLED=NO";

            if (id == 0x294 && byteIndex == 1)
                return "KNOWN:DIMMER_LEVEL raw=0x" + newValue.ToString("X2", CultureInfo.InvariantCulture);

            if (id == 0x324 && byteIndex == 0)
                return "KNOWN:COOLANT raw=0x" + newValue.ToString("X2", CultureInfo.InvariantCulture) +
                       " (~" + ((int)newValue - 40).ToString(CultureInfo.InvariantCulture) + "C)";

            if (id == 0x158)
                return "KNOWN:VEHICLE_SPEED_FRAME";

            if (id == 0x17C)
                return "KNOWN:ENGINE_RPM_STATUS_FRAME";

            if (id == 0x40C)
                return "KNOWN:VIN_BROADCAST";

            return "";
        }

        private void WriteFrameToLog(CanFrame f)
        {
            lock (_logLock)
            {
                if (_logWriter == null) return;

                StringBuilder data = new StringBuilder();
                for (int i = 0; i < f.Data.Length; i++)
                {
                    if (i != 0) data.Append(' ');
                    data.Append(f.Data[i].ToString("X2"));
                }

                _logWriter.Write(
                    f.HostSeconds.ToString("0.000000", CultureInfo.InvariantCulture));
                _logWriter.Write(",");
                _logWriter.Write(f.AdapterTimestamp.ToString(CultureInfo.InvariantCulture));
                _logWriter.Write(",");
                _logWriter.Write(f.CanId.ToString(f.Extended ? "X8" : "X3"));
                _logWriter.Write(",");
                _logWriter.Write(f.Extended ? "1" : "0");
                _logWriter.Write(",");
                _logWriter.Write(f.Data.Length.ToString(CultureInfo.InvariantCulture));
                _logWriter.Write(",");
                _logWriter.WriteLine(data.ToString());

                if ((_totalFrames & 0x3FF) == 0)
                    _logWriter.Flush();
            }
        }

        private static string Csv(string s)
        {
            if (s == null) return "";
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        }

        private void StopCapture()
        {
            _runReader = false;

            Thread thread = _readerThread;
            _readerThread = null;
            if (thread != null && thread.IsAlive)
            {
                if (!thread.Join(750))
                {
                    // Do not abort the thread. Closing the J2534 channel below normally
                    // releases a vendor DLL blocked in PassThruReadMsgs.
                }
            }

            if (_api != null)
            {
                try { _api.Dispose(); } catch { }
                _api = null;
            }

            _clock.Stop();

            _start.Enabled = true;
            _stop.Enabled = false;
            _deviceCombo.Enabled = true;
            _refreshDevices.Enabled = true;
            _browseDll.Enabled = true;
            _dllPath.Enabled = true;
            _baud.Enabled = true;
            _bothIds.Enabled = true;
            _tactrixSniff.Enabled = true;
            _status.Text = "Disconnected";
        }

        private void MainFormClosing(object sender, FormClosingEventArgs e)
        {
            StopLog();
            StopCapture();
        }
    }
}
