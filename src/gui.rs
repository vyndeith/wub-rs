#![windows_subsystem = "windows"]

use std::sync::atomic::{AtomicBool, Ordering};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE};
use windows::Win32::Graphics::Gdi::{
    CreateSolidBrush, DrawTextW, FillRect, GetStockObject, SetBkMode, SetTextColor, DEFAULT_GUI_FONT,
    DT_CENTER, DT_SINGLELINE, DT_VCENTER, HBRUSH, HGDIOBJ, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::DRAWITEMSTRUCT;
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::WindowsAndMessaging::*;

const EM_SETSEL: u32 = 0x00B1;
const EM_REPLACESEL: u32 = 0x00C2;
const ODS_SELECTED_BIT: u32 = 0x0001;

const ID_ENABLE: usize = 1;
const ID_DISABLE: usize = 2;
const ID_CHECK: usize = 3;
const ID_EDIT: usize = 4;

const WM_APPEND: u32 = WM_APP + 1;
const WM_DONE: u32 = WM_APP + 2;

const BG: u32 = rgb(28, 28, 30);
const EDIT_BG: u32 = rgb(18, 18, 20);
const TEXT: u32 = rgb(222, 222, 222);
const BTN: u32 = rgb(48, 48, 52);
const BTN_DOWN: u32 = rgb(72, 72, 78);

const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

static RUNNING: AtomicBool = AtomicBool::new(false);
static mut BG_BRUSH: isize = 0;
static mut EDIT_BRUSH: isize = 0;
static mut GUI_FONT: isize = 0;

fn main() {
    if !wublocker::is_elevated() {
        wublocker::relaunch_elevated();
        return;
    }
    unsafe {
        let hinstance = GetModuleHandleW(None).unwrap();
        BG_BRUSH = CreateSolidBrush(COLORREF(BG)).0 as isize;
        EDIT_BRUSH = CreateSolidBrush(COLORREF(EDIT_BG)).0 as isize;
        GUI_FONT = GetStockObject(DEFAULT_GUI_FONT).0 as isize;

        let class = w!("WublockerWindow");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance.into(),
            lpszClassName: class,
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap(),
            hbrBackground: HBRUSH(BG_BRUSH as *mut _),
            ..Default::default()
        };
        RegisterClassW(&wc);

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class,
            w!("wu-blocker"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            560,
            440,
            None,
            None,
            Some(hinstance.into()),
            None,
        )
        .unwrap();

        let dark: i32 = 1;
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &dark as *const _ as *const _,
            std::mem::size_of::<i32>() as u32,
        );

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

unsafe fn make_button(parent: HWND, id: usize, text: PCWSTR, hinst: isize) {
    let h = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        w!("BUTTON"),
        text,
        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_OWNERDRAW as u32),
        0,
        0,
        0,
        0,
        Some(parent),
        Some(HMENU(id as *mut _)),
        Some(windows::Win32::Foundation::HINSTANCE(hinst as *mut _)),
        None,
    )
    .unwrap();
    SendMessageW(h, WM_SETFONT, Some(WPARAM(GUI_FONT as usize)), Some(LPARAM(1)));
}

unsafe fn layout(hwnd: HWND) {
    let mut rc = windows::Win32::Foundation::RECT::default();
    let _ = GetClientRect(hwnd, &mut rc);
    let w = rc.right - rc.left;
    let h = rc.bottom - rc.top;
    let pad = 10;
    let bh = 40;
    let bw = (w - pad * 4) / 3;
    for (i, id) in [ID_ENABLE, ID_DISABLE, ID_CHECK].iter().enumerate() {
        if let Ok(btn) = GetDlgItem(Some(hwnd), *id as i32) {
            let x = pad + (bw + pad) * i as i32;
            let _ = MoveWindow(btn, x, pad, bw, bh, true);
        }
    }
    if let Ok(edit) = GetDlgItem(Some(hwnd), ID_EDIT as i32) {
        let y = pad * 2 + bh;
        let _ = MoveWindow(edit, pad, y, w - pad * 2, h - y - pad, true);
    }
}

unsafe fn append(edit: HWND, line: &str) {
    let end = GetWindowTextLengthW(edit);
    SendMessageW(edit, EM_SETSEL, Some(WPARAM(end as usize)), Some(LPARAM(end as isize)));
    let wide: Vec<u16> = (line.to_string() + "\r\n").encode_utf16().collect();
    let wide: Vec<u16> = wide.into_iter().chain(std::iter::once(0)).collect();
    SendMessageW(
        edit,
        EM_REPLACESEL,
        Some(WPARAM(0)),
        Some(LPARAM(wide.as_ptr() as isize)),
    );
}

fn start_worker(hwnd: HWND, id: usize) {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let hval = hwnd.0 as isize;
    std::thread::spawn(move || {
        wublocker::set_sink(move |line| unsafe {
            let boxed = Box::into_raw(Box::new(line.to_string()));
            let _ = PostMessageW(
                Some(HWND(hval as *mut _)),
                WM_APPEND,
                WPARAM(0),
                LPARAM(boxed as isize),
            );
        });
        let o = wublocker::Options::default();
        match id {
            ID_ENABLE => wublocker::enable(&o),
            ID_DISABLE => wublocker::disable(&o),
            ID_CHECK => wublocker::check(),
            _ => {}
        }
        wublocker::clear_sink();
        unsafe {
            let _ = PostMessageW(Some(HWND(hval as *mut _)), WM_DONE, WPARAM(0), LPARAM(0));
        }
    });
}

unsafe fn enable_buttons(hwnd: HWND, on: bool) {
    for id in [ID_ENABLE, ID_DISABLE, ID_CHECK] {
        if let Ok(b) = GetDlgItem(Some(hwnd), id as i32) {
            let _ = EnableWindow(b, on);
        }
    }
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CREATE => {
                let hinst = GetModuleHandleW(None).unwrap().0 as isize;
                make_button(hwnd, ID_ENABLE, w!("Enable"), hinst);
                make_button(hwnd, ID_DISABLE, w!("Disable"), hinst);
                make_button(hwnd, ID_CHECK, w!("Check"), hinst);
                let edit = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("EDIT"),
                    w!(""),
                    WS_CHILD
                        | WS_VISIBLE
                        | WS_VSCROLL
                        | WINDOW_STYLE(
                            (ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL) as u32,
                        ),
                    0,
                    0,
                    0,
                    0,
                    Some(hwnd),
                    Some(HMENU(ID_EDIT as *mut _)),
                    Some(windows::Win32::Foundation::HINSTANCE(hinst as *mut _)),
                    None,
                )
                .unwrap();
                SendMessageW(edit, WM_SETFONT, Some(WPARAM(GUI_FONT as usize)), Some(LPARAM(1)));
                LRESULT(0)
            }
            WM_SIZE => {
                layout(hwnd);
                LRESULT(0)
            }
            WM_COMMAND => {
                let id = (wp.0 & 0xFFFF) as usize;
                let code = (wp.0 >> 16) as u32;
                if code == BN_CLICKED && (id == ID_ENABLE || id == ID_DISABLE || id == ID_CHECK) {
                    enable_buttons(hwnd, false);
                    start_worker(hwnd, id);
                }
                LRESULT(0)
            }
            WM_DRAWITEM => {
                let dis = &*(lp.0 as *const DRAWITEMSTRUCT);
                let down = (dis.itemState.0 & ODS_SELECTED_BIT) != 0;
                let brush = CreateSolidBrush(COLORREF(if down { BTN_DOWN } else { BTN }));
                FillRect(dis.hDC, &dis.rcItem, brush);
                let _ = windows::Win32::Graphics::Gdi::DeleteObject(HGDIOBJ(brush.0));
                SetBkMode(dis.hDC, TRANSPARENT);
                SetTextColor(dis.hDC, COLORREF(TEXT));
                let label = match dis.CtlID as usize {
                    ID_ENABLE => "Enable",
                    ID_DISABLE => "Disable",
                    ID_CHECK => "Check",
                    _ => "",
                };
                let mut wtext: Vec<u16> = label.encode_utf16().collect();
                let mut rc = dis.rcItem;
                DrawTextW(dis.hDC, &mut wtext, &mut rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                LRESULT(1)
            }
            WM_CTLCOLOREDIT | WM_CTLCOLORSTATIC => {
                let hdc = windows::Win32::Graphics::Gdi::HDC(wp.0 as *mut _);
                SetTextColor(hdc, COLORREF(TEXT));
                windows::Win32::Graphics::Gdi::SetBkColor(hdc, COLORREF(EDIT_BG));
                LRESULT(EDIT_BRUSH)
            }
            WM_APPEND => {
                let boxed = Box::from_raw(lp.0 as *mut String);
                if let Ok(edit) = GetDlgItem(Some(hwnd), ID_EDIT as i32) {
                    append(edit, &boxed);
                }
                LRESULT(0)
            }
            WM_DONE => {
                enable_buttons(hwnd, true);
                RUNNING.store(false, Ordering::SeqCst);
                if let Ok(edit) = GetDlgItem(Some(hwnd), ID_EDIT as i32) {
                    append(edit, "------------------------------");
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}
