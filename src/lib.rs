use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule};
use pyo3::wrap_pyfunction;

fn get_logger<'py>(py: Python<'py>) -> PyResult<&'py PyAny> {
    let logging = py.import("logging")?;
    let logger = logging.call_method1("getLogger", ("bomiot_asgi",))?;
    Ok(logger)
}

fn try_import_app(py: Python<'_>, module_path: &str, attr_name: &str) -> PyResult<Option<PyObject>> {
    let logger = get_logger(py)?;
    let importlib = py.import("importlib")?;

    let module = match importlib.call_method1("import_module", (module_path,)) {
        Ok(m) => m,
        Err(e) => {
            logger.call_method1(
                "warning",
                (format!("{} not loaded: {}", module_path, e.value(py)),),
            )?;
            return Ok(None);
        }
    };

    let app = match module.getattr(attr_name) {
        Ok(a) => a,
        Err(e) => {
            logger.call_method1(
                "warning",
                (format!("{} not found in {}: {}", attr_name, module_path, e.value(py)),),
            )?;
            return Ok(None);
        }
    };

    Ok(Some(app.into()))
}

#[pyfunction]
fn regenerate_auth_key(py: Python, file_path: &str) -> PyResult<bool> {
    let bomiot_token = match py.import("bomiot_token") {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };
    let keys = match bomiot_token.call_method1("encrypt_info", ()) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };
    let (community_key, sponsor_key): (String, String) = match keys.extract() {
        Ok(t) => t,
        Err(_) => return Ok(false),
    };
    let content = format!(
        "COMMUNITY_KEY = \"{}\"\nSPONSOR_KEY = \"{}\"\n",
        escape_py_string_literal(&community_key),
        escape_py_string_literal(&sponsor_key),
    );
    match std::fs::write(file_path, content) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// 把 bomiot_token 返回的原始字符串转义成安全的 Python 双引号字符串字面量内容
/// 主要处理 \" 和 \\ 换行等，避免拼出不合法的 auth_key.py
fn escape_py_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

use serde::Deserialize;

#[derive(Deserialize, Default)]
struct AuthResp {
    #[serde(default)]
    expired: Option<i64>,
}

#[pyfunction]
fn check_auth_via_bomiot_server(
    community_key: &str,
    sponsor_key: &str,
) -> PyResult<(bool, i64)> {
    /// 把 JSON 字符串中 "、\、控制字符做安全转义，防止拼出不合法的请求体
    fn json_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out
    }

    use std::time::Duration;

    // 任何异常/错误一律兜底返回 (false, 0)
    let fallback = || (false, 0);

    let body = format!(
        "{{\"COMMUNITY_KEY\":\"{}\",\"SPONSOR_KEY\":\"{}\"}}",
        json_escape(community_key),
        json_escape(sponsor_key),
    );

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Ok(fallback()),
    };

    let result = (|| -> reqwest::Result<(bool, i64)> {
        let resp = client
            .post("https://www.bomiot.com/auth/")
            .header("Authed", "Bomiot")
            .header("Content-Type", "application/json")
            .body(body)
            .send()?
            .error_for_status()?; // HTTP 非 2xx → 算失败 → false

        let data: AuthResp = resp.json().unwrap_or_default();
        Ok((true, data.expired.unwrap_or(0)))
    })();

    Ok(result.unwrap_or_else(|_| fallback()))
}

#[pyfunction]
fn fetch_projectlist_ping() -> PyResult<String> {
    use std::time::Duration;
    let result = (|| -> reqwest::Result<String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()?;
        let resp = client
            .get("https://www.bomiot.com/projectlist/")
            .send()?;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        Ok(format!("[projectlist] HTTP {} body={}", status.as_u16(), body))
    })();
    Ok(result.unwrap_or_else(|e| format!("[projectlist] request failed: {}", e)))
}

#[pyfunction]
fn detect_nuitka_and_set_is_lan(py: Python) -> PyResult<()> {
    let is_nuitka = py
        .import("__main__")
        .map(|m| m.hasattr("__compiled__").unwrap_or(false))
        .unwrap_or(false);
    std::env::set_var("IS_LAN", if is_nuitka { "true" } else { "false" });
    Ok(())
}

#[pyfunction]
fn create_asgi_application() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let logger = get_logger(py)?;

        let django_asgi = py.import("django.core.asgi")?;
        let starlette_applications = py.import("starlette.applications")?;
        let starlette_routing = py.import("starlette.routing")?;
        let wsgi_middleware = py.import("a2wsgi")?.getattr("WSGIMiddleware")?;

        let get_asgi_application = django_asgi.getattr("get_asgi_application")?;
        let http_application = get_asgi_application.call0()?;

        let fastapi_app =
            try_import_app(py, "greaterwms.fastapi_app.main", "fastapi_app")?;

        let flask_app =
            try_import_app(py, "greaterwms.flask_app.main", "flask_app")?;

        let routes = PyList::empty(py);
        let mount_class = starlette_routing.getattr("Mount")?;

        if let Some(app) = fastapi_app {
            let fastapi_mount = mount_class.call1(("/fastapi", app))?;
            routes.append(fastapi_mount)?;
            logger.call_method1("info", ("FastAPI app mounted at /fastapi",))?;
        }

        if let Some(app) = flask_app {
            let flask_wsgi = wsgi_middleware.call1((app,))?;
            let flask_mount = mount_class.call1(("/flask", flask_wsgi))?;
            routes.append(flask_mount)?;
            logger.call_method1("info", ("Flask app mounted at /flask",))?;
        }

        let django_mount = mount_class.call1(("/", http_application))?;
        routes.append(django_mount)?;

        // 定义验证+真实IP中间件
        py.run(
            "
import os
import time
import importlib.util
import bomiot_token
from bomiot_asgi import regenerate_auth_key, detect_nuitka_and_set_is_lan, check_auth_via_bomiot_server, fetch_projectlist_ping
import threading

def parse_key_attr(module, attr_name):
    if not hasattr(module, attr_name):
        return None
    try:
        result = bomiot_token.verify_info(getattr(module, attr_name))
        if isinstance(result, tuple) and len(result) >= 2:
            mac_str = str(result[0]).strip()
            ts_str = str(result[1]).strip()
            try:
                timestamp = int(ts_str)
            except (ValueError, TypeError):
                timestamp = 0
            return (mac_str, timestamp)
        return None
    except Exception:
        return None

def parse_key_file(file_path):
    if not os.path.isfile(file_path):
        return None
    try:
        spec = importlib.util.spec_from_file_location(os.path.basename(file_path), file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # 同时取原始字符串（供认证接口 POST 使用）和解密数据（判断文件有效性）
        raw_community = getattr(module, 'COMMUNITY_KEY', None)
        raw_sponsor = getattr(module, 'SPONSOR_KEY', None)
        if raw_community is None or raw_sponsor is None:
            return None
        community_data = parse_key_attr(module, 'COMMUNITY_KEY')
        sponsor_data = parse_key_attr(module, 'SPONSOR_KEY')
        if community_data is None or sponsor_data is None:
            return None
        return (str(raw_community), str(raw_sponsor))
    except Exception as e:
        print(f'[Warning] Failed to parse {os.path.basename(file_path)}: {e}')
        return None

def install_payment_blocker():
    '''使用 sys.addaudithook 拦截对支付域名的出站请求，防止用户自建支付体系。'''
    import sys

    _BLOCKED_DOMAINS = frozenset([
        # 支付宝【只拦支付专用子域，放行 auth.alipay.com / openauth.alipay.com 等登录域名】
        'openapi.alipay.com',
        'mapi.alipay.com',
        'pcreditapi.alipay.com',
        'bizhk.alipay.com',
        'intlmapi.alipay.com',
        'rmbapi.alipay.com',
        # 微信支付商户平台【不含普通微信登录 api.weixin.qq.com / open.weixin.qq.com】
        'api.mch.weixin.qq.com',
        'apihk.mch.weixin.qq.com',
        'pay.weixin.qq.com',
        'hongbao.weixin.qq.com',
        # 银联 / 快钱网关
        'api.unionpay.com',
        'gateway.99bill.com',
        'acp.99bill.com',
        # 易宝 / Ping++ / 京东支付 等第三方【只拦支付 API 子域，不放官网/登录】
        'ok.yeepay.com',
        'ybupload.yeepay.com',
        'api.pingxx.com',
        'pay.jd.com',
        'mapi.jdpay.com',
        'www.paypal.com',
        'api.paypal.com',
    ])

    def _is_blocked(host):
        if not host:
            return False
        h = str(host).lower()
        for d in _BLOCKED_DOMAINS:
            if h == d or h.endswith('.' + d):
                return True
        return False

    def _payment_audit_hook(event, args):
        if event != 'socket.connect':
            return
        try:
            _sock, address = args
        except Exception:
            return
        if not address or not isinstance(address, tuple) or len(address) < 1:
            return
        host = address[0]
        if _is_blocked(host):
            raise PermissionError(
                f'[Bomiot] Outbound connection to payment domain blocked: {host}'
            )

    try:
        sys.addaudithook(_payment_audit_hook)
    except Exception:
        pass

def init_auth_key():
    detect_nuitka_and_set_is_lan()

    from django.conf import settings
    working_space = settings.WORKING_SPACE
    auth_key_path = os.path.join(working_space, 'auth_key.py')
    # 启动时发送一次 https://www.bomiot.com 认证请求，设置 AUTHED
    is_lan = os.environ.get('IS_LAN', 'false') == 'true'
    if not is_lan:
        # 保证 auth_key.py 一定存在：有就校验解密，缺/坏就重生；不发认证 POST
        if not os.path.isfile(auth_key_path):
            regenerate_auth_key(auth_key_path)
        else:
            raw_keys_local = parse_key_file(auth_key_path)
            if raw_keys_local is None:
                regenerate_auth_key(auth_key_path)
        os.environ['AUTHED'] = 'true'
        return

    raw_keys = None
    if os.path.isfile(auth_key_path):
        raw_keys = parse_key_file(auth_key_path)   # 单次 import：取原始 key 字符串 + 校验解密

    if raw_keys is None:
        regenerate_auth_key(auth_key_path)          # 解密失败/文件不存在 → 重生
        if os.path.isfile(auth_key_path):
            raw_keys = parse_key_file(auth_key_path)  # 重生后再解析一次（解密+取原始）

    if raw_keys is not None:
        community_key, sponsor_key = raw_keys
        ok, expired_ts = check_auth_via_bomiot_server(community_key, sponsor_key)
        if ok:
            now_ts = int(time.time())
            if expired_ts > now_ts:
                os.environ['AUTHED'] = 'true'
            else:
                os.environ['AUTHED'] = 'false'
        else:
            os.environ['AUTHED'] = 'false'
    else:
        if os.path.isfile(auth_key_path):
            # 文件存在但两次都读不出 key（格式损坏）
            os.environ['AUTHED'] = 'false'
        else:
            # 文件未生成（如无网卡 encrypt_info 失败）→ 兜底放行
            os.environ['AUTHED'] = 'true'

class VerifyMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        path = scope.get('path', '')

        if path == '/' or path == '/favicon.ico' or any(path.startswith(prefix) for prefix in ('/css/', '/js/', '/assets/', '/statics/', '/fonts/', '/icons/', '/static/', '/media/', '/projectlist/', '/md/')):
            if path.startswith('/projectlist'):
                def _ping_and_print():
                    try:
                        print(fetch_projectlist_ping(), flush=True)
                    except Exception as _e:
                        print(f'[projectlist] hook error: {_e}', flush=True)
                threading.Thread(target=_ping_and_print, daemon=True).start()
            await self.app(scope, receive, send)
            return

        if os.environ.get('IS_LAN', 'false') != 'true':
            await self.app(scope, receive, send)
            return

        if os.environ.get('AUTHED', 'false') == 'true':
            await self.app(scope, receive, send)
            return

        from starlette.responses import JSONResponse
        # 根据请求头 Language（GreaterWMS 后端约定：zh-CN / en-US）返回对应语言的 detail
        _lang = 'en-US'
        for _h, _v in scope.get('headers', []):
            if _h == b'language':
                try:
                    _lang = _v.decode('utf-8', 'ignore')
                except Exception:
                    pass
                break
        if _lang == 'zh-CN':
            _detail = '赞助已过期，请联系续费'
        else:
            _detail = 'Sponsorship has expired. Please contact support to renew.'
        response = JSONResponse({'detail': _detail}, status_code=200)
        await response(scope, receive, send)
    "
    , None, None)?;

        py.run("init_auth_key()", None, None)?;
        py.run("install_payment_blocker()", None, None)?;

        let middleware_class = py.import("starlette.middleware")?.getattr("Middleware")?;
        let verify_middleware = py.eval("VerifyMiddleware", None, None)?;
        let middleware_list = PyList::empty(py);
        middleware_list.append(middleware_class.call1((verify_middleware,))?)?;

        let starlette_class = starlette_applications.getattr("Starlette")?;
        let app_kwargs = PyDict::new(py);
        app_kwargs.set_item("routes", routes)?;
        app_kwargs.set_item("middleware", middleware_list)?;
        let application = starlette_class.call((), Some(app_kwargs))?;

        logger.call_method1("info", ("ASGI application created successfully",))?;

        Ok(application.into())
    })
}

#[pymodule]
fn bomiot_asgi(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_asgi_application, m)?)?;
    m.add_function(wrap_pyfunction!(regenerate_auth_key, m)?)?;
    m.add_function(wrap_pyfunction!(detect_nuitka_and_set_is_lan, m)?)?;
    m.add_function(wrap_pyfunction!(check_auth_via_bomiot_server, m)?)?;
    m.add_function(wrap_pyfunction!(fetch_projectlist_ping, m)?)?;

    let application = create_asgi_application()?;
    m.add("application", application)?;
    Ok(())
}
