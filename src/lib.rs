use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::wrap_pyfunction;

/// 支付域名黑名单（编译期常量，不写进 Python 注入字符串，strings 无法整表 dump）
/// 匹配规则：精确匹配 或 子域后缀匹配（例如 openapi.alipay.com 命中 alipay.com / openapi.alipay.com）
const BLOCKED_PAYMENT_DOMAINS: &[&str] = &[
    // ── 支付宝支付专用域名 ──────────────────────────────────────────────────────
    // （注意：auth.alipay.com / openauth.alipay.com / openhome.alipay.com 是支付宝登录 OAuth，不在这里）
    "openapi.alipay.com",
    "openapi-sandbox.dl.alipaydev.com",   // 支付宝沙箱 V3（openapi.alipaydev.com）
    "openapi.alipaydev.com",              // 支付宝沙箱（兼容写法）
    "mapi.alipay.com",
    "mopenapi.alipay.com",
    "pcreditapi.alipay.com",
    "bizhk.alipay.com",
    "intlmapi.alipay.com",
    "rmbapi.alipay.com",
    "rmbgateway.alipay.com",
    "opendocs.alipay.com",
    "amsdk-pc.alipay.com",
    "h5api.alipay.com",
    // ── 微信支付专用域名 ──────────────────────────────────────────────────────
    // （注意：api.weixin.qq.com / open.weixin.qq.com 是普通微信登录/小程序，不在这里）
    "api.mch.weixin.qq.com",              // 微信支付 V2/V3 商户 API
    "api2.mch.weixin.qq.com",
    "apihk.mch.weixin.qq.com",            // 微信支付香港节点
    "apitest.mch.weixin.qq.com",          // 微信支付沙箱
    "fraud.mch.weixin.qq.com",            // 微信支付风控
    "pay.weixin.qq.com",
    "payapp.weixin.qq.com",
    "hongbao.weixin.qq.com",
    "sp.sparta.html5.qq.com",             // 微信 Q 币/支付跳转
    // ── 银联 / 快钱 / 云闪付 ─────────────────────────────────────────────────
    "gateway.95516.com",                  // 银联云闪付官方网关（UnionPay 商户 SDK）
    "upacp.95516.com",                    // 银联全渠道 UPACP
    "qr.95516.com",                       // 银联二维码
    "open.unionpay.com",                  // 银联开放平台
    "merchant.unionpay.com",              // 银联商户后台接口
    "api.unionpay.com",
    "mpos.unionpay.com",
    "gateway.99bill.com",                 // 快钱
    "acp.99bill.com",
    "svr.99bill.com",
    // ── 通联支付 Allinpay ────────────────────────────────────────────────────
    "api.allinpay.com",
    "aipg.allinpay.com",
    "srv.allinpay.com",
    "vsp.allinpay.com",
    // ── 汇付天下 Huifu ───────────────────────────────────────────────────────
    "api.huifupay.com",
    "mert.huifupay.com",
    "trade.huifupay.com",
    "cloudpnr.huifupay.com",
    // ── 易宝支付 YeePay ─────────────────────────────────────────────────────
    "api.yeepay.com",
    "ok.yeepay.com",
    "www.yeepay.com",
    "ybupload.yeepay.com",
    // ── 连连支付 LianLianPay ─────────────────────────────────────────────────
    "openapi.lianlianpay.com",
    "trx.lianlianpay.com",
    "v2.lianlianpay.com",
    "acp.lianpay.com",
    "payment.lianlianpay.com",
    // ── 拉卡拉 Lakala ────────────────────────────────────────────────────────
    "api.lakala.com",
    "trade.lakala.com",
    "m.lakala.com",
    "merchant.lakala.com",
    // ── 京东支付 / 京东金融 ──────────────────────────────────────────────────
    "pay.jd.com",
    "api.jdpay.com",
    "mapi.jdpay.com",
    "paygate.jd.com",
    "ms.jr.jd.com",
    // ── 百度度小满 / 百度钱包 / 百付宝 ───────────────────────────────────────
    "dxmpay.duxiaoman.com",
    "pay.duxiaoman.com",
    "www.baifubao.com",
    "api.baifubao.com",
    // ── 聚合 / SaaS 支付 ────────────────────────────────────────────────────
    "api.pingxx.com",                     // Ping++
    "pay.youzanyun.com",                  // 有赞支付
    "open.youzanyun.com",
    "api.weimob.com",                     // 微盟
    "pay.weimob.com",
    "api.shouqianba.com",                 // 收钱吧
    "m.shouqianba.com",
    "api.shengpay.com",                   // 盛付通
    "www.shengpay.com",
    // ── 海外支付（PayPal / Stripe / 2Checkout / Google Pay） ────────────────
    "www.paypal.com",
    "api.paypal.com",
    "api.sandbox.paypal.com",             // PayPal 沙箱
    "svcs.paypal.com",
    "payflowpro.paypal.com",
    "pilot-payflowpro.paypal.com",
    "api.stripe.com",                     // Stripe
    "files.stripe.com",
    "checkout.stripe.com",
    "connect.stripe.com",
    "api.2checkout.com",                  // 2Checkout (Verifone)
    "secure.2checkout.com",
    "pay.google.com",                     // Google Pay 商家接口
    "api.mollie.com",                     // Mollie（欧洲）
    "api.adyen.com",                      // Adyen（跨境）
    "checkoutshopper-live.adyen.com",
    "checkoutshopper-test.adyen.com",
    "api.worldpay.com",                   // Worldpay
];

fn is_payment_domain_blocked(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let h = host.to_ascii_lowercase();
    for d in BLOCKED_PAYMENT_DOMAINS {
        let d = *d;
        if h == d || h.ends_with(&format!(".{}", d)) {
            return true;
        }
    }
    false
}

/// 暴露给 Python 注入侧判断：给定 host（域名或 IPv4/IPv6 字符串），是否命中 Rust 编译期支付黑名单。
/// Python 侧 audit hook(event, args) 逻辑自己写原生 Python，不要在这里用 PyO3 class __call__，避免 CPython
/// sys.addaudithook 的 C 快速调用路径下 PyO3 自定义类的参数适配歧义（expected 1 arg got 0 影子错误）。
#[pyfunction]
fn is_payment_domain_blocked_py(host: &str) -> bool {
    is_payment_domain_blocked(host)
}

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

#[pyfunction]
fn check_auth_via_bomiot_server(
    community_key: &str,
    sponsor_key: &str,
) -> PyResult<(bool, i64)> {

    use std::time::Duration;

    // 任何异常/错误一律兜底返回 (false, 0)
    let fallback = || (false, 0);

    let body = format!(
        "{{\"COMMUNITY_KEY\":\"{}\",\"SPONSOR_KEY\":\"{}\"}}",
        json_escape(community_key),
        json_escape(sponsor_key),
    );

    let client = match reqwest::blocking::Client::builder()
        .user_agent(concat!("bomiot_asgi/", env!("CARGO_PKG_VERSION")))
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
            .header("Accept", "application/json")
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
fn fetch_projectlist_ping(community_key: &str, sponsor_key: &str) -> PyResult<String> {
    use std::time::Duration;
    let body = format!(
        "{{\"COMMUNITY_KEY\":\"{}\",\"SPONSOR_KEY\":\"{}\"}}",
        json_escape(community_key),
        json_escape(sponsor_key),
    );
    let result = (|| -> reqwest::Result<String> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(concat!("bomiot_asgi/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(3))
            .build()?;
        let resp = client
            .post("https://www.bomiot.com/auth/")
            .header("Authed", "Bomiot")
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(body)
            .send()?;
        let status = resp.status();
        let resp_body = resp.text().unwrap_or_default();
        Ok(format!("[projectlist] HTTP {} body={}", status.as_u16(), resp_body))
    })();
    Ok(result.unwrap_or_else(|e| format!("[projectlist] request failed: {}", e)))
}

#[pyfunction]
fn detect_nuitka_and_set_is_lan(py: Python) -> PyResult<()> {
    // 方法 1：Nuitka 官方推荐 - __main__.__compiled__ 存在
    let method1 = py
        .import("__main__")
        .map(|m| m.hasattr("__compiled__").unwrap_or(false))
        .unwrap_or(false);

    // 方法 2：Nuitka launcher 启动时注入的 NUITKA_LAUNCH_TOKEN 环境变量非空
    let method2 = std::env::var("NUITKA_LAUNCH_TOKEN")
        .map(|v| !v.is_empty())
        .unwrap_or(false);

    // 方法 3：能 import __nuitka__ 专属模块（Nuitka 编译过的进程都会注入这个模块）
    let method3 = py.import("__nuitka__").is_ok();

    let is_nuitka = method1 || method2 || method3;

    if is_nuitka {
        // 明确是 Nuitka → 权威写 true，覆盖任何外部预置
        std::env::set_var("IS_LAN", "true");
    } else {
        // 不是 Nuitka → 仅当外层根本没设 IS_LAN 时才写 false 默认值
        // 如果外层（launcher 层）已经手动设过值，原样保留，绝不覆盖
        if std::env::var("IS_LAN").is_err() {
            std::env::set_var("IS_LAN", "false");
        }
    }
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
        // 注意：这里不能 py.import("bomiot_asgi")，因为 create_asgi_application 理论上
        // 仍可能在 #[pymodule] bomiot_asgi 初始化期间被显式调用（虽然我们已不再自动调用），
        // 那样会命中 Python 的 "partially initialized module" 拦截。
        // 安全做法：直接从 sys.modules 字典里取（不触发 import 语义）。
        let globals = PyDict::new(py);
        // PyO3 0.19：call_method1 / PyDict::get_item 都是稳定 API（0.19 文档里有），
        // 但不用 0.20+ 才有的 Bound / into_pyobject。取值统一转 PyObject，
        // 再用 .as_ref(py) 取 &PyAny，下面 getattr 就直接跑。
        let sys = py.import("sys")?;
        let modules: &PyDict = sys
            .getattr("modules")?
            .downcast::<PyDict>()
            .map_err(|_| pyo3::exceptions::PyTypeError::new_err("sys.modules is not a dict"))?;
        let alt_key = "bomiot_asgi.bomiot_asgi";
        // 目录包子模块：优先 sys.modules['bomiot_asgi.bomiot_asgi']（add_function 真注册的 PyModule）
        // 单文件扩展：sys.modules['bomiot_asgi']
        // 这一步避免目录包 partially initialized 时，顶层 bomiot_asgi 属性还没复制完、
        // get regenerate_auth_key 空触发 circular import。
        let self_module_obj: PyObject = {
            let alt = modules.get_item(alt_key);
            if let Some(v) = alt {
                v.to_object(py)
            } else {
                let top = modules.get_item("bomiot_asgi");
                match top {
                    Some(v) => v.to_object(py),
                    None => {
                        return Err(pyo3::exceptions::PyImportError::new_err(
                            "bomiot_asgi module not in sys.modules",
                        ))
                    }
                }
            }
        };
        let self_module = self_module_obj.as_ref(py);
        globals.set_item("__builtins__", py.eval("__import__('builtins')", None, None)?)?;
        globals.set_item(
            "regenerate_auth_key",
            self_module.getattr("regenerate_auth_key")?,
        )?;
        globals.set_item(
            "detect_nuitka_and_set_is_lan",
            self_module.getattr("detect_nuitka_and_set_is_lan")?,
        )?;
        globals.set_item(
            "check_auth_via_bomiot_server",
            self_module.getattr("check_auth_via_bomiot_server")?,
        )?;
        globals.set_item(
            "fetch_projectlist_ping",
            self_module.getattr("fetch_projectlist_ping")?,
        )?;
        py.run(
            "
import os
import time
import importlib.util
import bomiot_token
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

def parse_build_json(file_path):
    # 从 build.json 读取 COMMUNITY_KEY / SPONSOR_KEY
    if not os.path.isfile(file_path):
        return None
    try:
        import json as _json
        with open(file_path, 'r', encoding='utf-8') as _f:
            _data = _json.load(_f)
        _ck = _data.get('COMMUNITY_KEY')
        _sk = _data.get('SPONSOR_KEY')
        if not _ck or not _sk:
            return None
        return (str(_ck), str(_sk))
    except Exception as e:
        print(f'[Warning] Failed to parse {os.path.basename(file_path)}: {e}')
        return None

def install_payment_blocker():
    import sys
    try:
        # 直接从 sys.modules 拿本模块对象，完全不走 import 路径，避免触发任何模块级
        # __getattr__ / __init__.py 重新导入副作用（特别是在 PEP 562 lazy application
        # 还没完成初始化的阶段）。
        _self = sys.modules.get('bomiot_asgi') or sys.modules.get('bomiot_asgi.bomiot_asgi')
        if _self is None:
            return
        _blocked = getattr(_self, 'is_payment_domain_blocked_py', None)
        if _blocked is None:
            return
    except Exception:
        return

    def audit_hook(event, args):
        if event not in ('socket.connect', 'socket.sendto'):
            return
        try:
            address = args[1]
        except Exception:
            return
        if not isinstance(address, tuple) or len(address) < 2:
            return
        host = address[0]
        if not isinstance(host, str) or not host:
            return
        try:
            hit = _blocked(host)
        except Exception:
            hit = False
        if hit:
            raise PermissionError(
                '[Bomiot] Outbound connection to payment domain blocked: ' + host
            )

    sys.addaudithook(audit_hook)

# init_auth_key 硬锁：全进程只跑一次，防止任何情况下（模块 reload / 手动重复调用 / 逻辑误触发）
# 在请求期间重复发 POST /auth/；只有 IS_LAN=true 且确实是启动首次执行时才会发认证请求。
_init_auth_key_done = False

def init_auth_key():
    global _init_auth_key_done
    if _init_auth_key_done:
        return
    _init_auth_key_done = True

    detect_nuitka_and_set_is_lan()

    # WORKING_SPACE 兜底：bomiot_example / GreaterWMS 配置了 django.conf.settings.WORKING_SPACE
    # 但裸环境（比如 debug import bomiot_asgi 没启 Django）下 settings 可能没配置、甚至
    # django.setup() 都没调。用 try/except 三级兜底：settings.WORKING_SPACE →
    # settings.BASE_DIR → os.getcwd()，保证 init_auth_key 读取 auth_key.py 的路径
    # 绝不会因为 settings 没配让 create_asgi_application 直接抛 Exception（那样 #[pymodule]
    # 注册函数阶段直接 return Err，上层 from .bomiot_asgi import * 就会看到
    # 扩展模块没有 regenerate_auth_key 等属性 → circular 报错）。
    try:
        from django.conf import settings as _dj_settings
        working_space = str(getattr(_dj_settings, 'WORKING_SPACE', None) or
                            getattr(_dj_settings, 'BASE_DIR', None) or
                            os.getcwd())
    except Exception:
        working_space = os.getcwd()
    auth_key_path = os.path.join(working_space, 'auth_key.py')

    # 启动时根据 IS_LAN 决定认证流程
    is_lan = os.environ.get('IS_LAN', 'false') == 'true'
    if not is_lan:
        # 云端/开发：保证 auth_key.py 存在（缺/坏就重生），不发请求，直接放行
        if not os.path.isfile(auth_key_path):
            regenerate_auth_key(auth_key_path)
        else:
            raw_keys_local = parse_key_file(auth_key_path)
            if raw_keys_local is None:
                regenerate_auth_key(auth_key_path)
        os.environ['AUTHED'] = 'true'
        return

    # Nuitka 打包：读取 build.json → 发请求 → 校验 expired
    build_json_path = os.path.join(working_space, 'build.json')
    raw_keys = parse_build_json(build_json_path)
    if raw_keys is None:
        # build.json 不存在或解析失败 → 直接不放行
        os.environ['AUTHED'] = 'false'
        return

    community_key, sponsor_key = raw_keys
    ok, expired_ts = check_auth_via_bomiot_server(community_key, sponsor_key)
    if not ok:
        # 请求失败（超时/网络错误）→ 不放行
        os.environ['AUTHED'] = 'false'
        return

    now_ts = int(time.time())
    if expired_ts > now_ts:
        os.environ['AUTHED'] = 'true'
    else:
        os.environ['AUTHED'] = 'false'

class VerifyMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        path = scope.get('path', '')

        # 静态白名单：/projectlist（含无尾斜形式）一并放行，不再发送 ping 请求
        _static_whitelist = (
            path == '/' or path == '/favicon.ico' or path == '/projectlist' or
            any(path.startswith(prefix) for prefix in (
                '/css/', '/js/', '/assets/', '/statics/',
                '/fonts/', '/icons/', '/static/', '/media/',
                '/projectlist/', '/md/',
            ))
        )
        if _static_whitelist:
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
    , Some(&globals), None)?;

        py.run("init_auth_key()", Some(&globals), None)?;

        let middleware_class = py.import("starlette.middleware")?.getattr("Middleware")?;
        let verify_middleware = py.eval("VerifyMiddleware", Some(&globals), None)?;
        let middleware_list = PyList::empty(py);
        middleware_list.append(middleware_class.call1((verify_middleware,))?)?;

        let starlette_class = starlette_applications.getattr("Starlette")?;
        let app_kwargs = PyDict::new(py);
        app_kwargs.set_item("routes", routes)?;
        app_kwargs.set_item("middleware", middleware_list)?;
        let application = starlette_class.call((), Some(app_kwargs))?;

        logger.call_method1("info", ("ASGI application created successfully",))?;

        // 无论扩展模块以"单文件 bomiot_asgi.pyd"形态安装，
        // 还是"目录包 bomiot_asgi/__init__.py + bomiot_asgi/bomiot_asgi.pyd 子模块"形态安装，
        // 都把真正的 ASGI application 对象直接写进两个模块对象的 __dict__['application']。
        // 这样 uvicorn import bomiot_asgi:application 时直接命中 __dict__ 属性（存在），
        // 不需要依赖 PEP 562 模块级 __getattr__ 的 CPython 实现细节。
        py.run(
            "
import sys as _sys
_top = _sys.modules.get('bomiot_asgi')
_alt = _sys.modules.get('bomiot_asgi.bomiot_asgi')
for _m in (_top, _alt):
    if _m is not None:
        try:
            setattr(_m, 'application', application)
        except Exception:
            pass
",
            Some(&globals),
            None,
        )?;

        Ok(application.into())
    })
}

#[pymodule]
fn bomiot_asgi(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_asgi_application, m)?)?;
    m.add_function(wrap_pyfunction!(regenerate_auth_key, m)?)?;
    m.add_function(wrap_pyfunction!(detect_nuitka_and_set_is_lan, m)?)?;
    m.add_function(wrap_pyfunction!(check_auth_via_bomiot_server, m)?)?;
    m.add_function(wrap_pyfunction!(fetch_projectlist_ping, m)?)?;
    m.add_function(wrap_pyfunction!(is_payment_domain_blocked_py, m)?)?;

    // __all__ 只含函数，不含 application。
    // application 放进 __all__ 会导致 from .bomiot_asgi import * 在 #[pymodule]
    // 执行期间就 getattr('application') → 过早触发 create_asgi_application()
    // → Django setup 回撞 partially initialized 顶层包 → circular import。
    let __all__: Vec<&str> = vec![
        "create_asgi_application",
        "regenerate_auth_key",
        "detect_nuitka_and_set_is_lan",
        "check_auth_via_bomiot_server",
        "fetch_projectlist_ping",
        "is_payment_domain_blocked_py",
    ];
    m.add("__all__", __all__.to_object(py))?;

    // PEP 562 __getattr__：uvicorn getattr(bomiot_asgi, 'application') 时才构造。
    // 此时 __init__.py 已执行完，顶层包完全初始化，Django import 不会回撞。
    py.run(
        "
import sys as _sys
_top = _sys.modules.get('bomiot_asgi')
_alt = _sys.modules.get('bomiot_asgi.bomiot_asgi')
_mod = _alt or _top
_app = None

def __bomiot_asgi_module_getattr__(name):
    global _app
    if name != 'application':
        raise AttributeError(f\"module 'bomiot_asgi' has no attribute '{name}'\")
    if _app is None:
        _app = _mod.create_asgi_application()
        for _m in (_top, _alt):
            if _m is not None:
                try:
                    setattr(_m, 'application', _app)
                except Exception:
                    pass
    return _app

if _top is not None:
    try:
        setattr(_top, '__getattr__', __bomiot_asgi_module_getattr__)
    except Exception:
        pass
",
        None,
        None,
    )?;
    let module_getattr = py.eval("__bomiot_asgi_module_getattr__", None, None)?;
    m.add("__getattr__", module_getattr)?;

    // 模块级即安装支付拦截 hook：import bomiot_asgi 就装 audit_hook，
    // 纯 Python 注入（黑名单 tuple 直接内联 + 精确/子域匹配）。
    // 不依赖 sys.modules getattr / Rust PyObject 传参，避免 partially
    // initialized 时属性没复制完或 install_locals 闭包捕获失败。
    py.run(
        "
import sys as _sys

_BLOCKED_PAYMENT_DOMAINS = (
    # 支付宝支付专用
    'openapi.alipay.com',
    'openapi-sandbox.dl.alipaydev.com',
    'openapi.alipaydev.com',
    'mapi.alipay.com',
    'mopenapi.alipay.com',
    'pcreditapi.alipay.com',
    'bizhk.alipay.com',
    'intlmapi.alipay.com',
    'rmbapi.alipay.com',
    'rmbgateway.alipay.com',
    'opendocs.alipay.com',
    'amsdk-pc.alipay.com',
    'h5api.alipay.com',
    # 微信支付专用
    'api.mch.weixin.qq.com',
    'api2.mch.weixin.qq.com',
    'apihk.mch.weixin.qq.com',
    'apitest.mch.weixin.qq.com',
    'fraud.mch.weixin.qq.com',
    'pay.weixin.qq.com',
    'payapp.weixin.qq.com',
    'hongbao.weixin.qq.com',
    'sp.sparta.html5.qq.com',
    # 银联/快钱/云闪付
    'gateway.95516.com',
    'upacp.95516.com',
    'qr.95516.com',
    'open.unionpay.com',
    'merchant.unionpay.com',
    'api.unionpay.com',
    'mpos.unionpay.com',
    'gateway.99bill.com',
    'acp.99bill.com',
    'svr.99bill.com',
    # 通联
    'api.allinpay.com',
    'aipg.allinpay.com',
    'srv.allinpay.com',
    'vsp.allinpay.com',
    # 汇付天下
    'api.huifupay.com',
    'mert.huifupay.com',
    'trade.huifupay.com',
    'cloudpnr.huifupay.com',
    # 易宝
    'api.yeepay.com',
    'ok.yeepay.com',
    'www.yeepay.com',
    'ybupload.yeepay.com',
    # 连连
    'openapi.lianlianpay.com',
    'trx.lianlianpay.com',
    'v2.lianlianpay.com',
    'acp.lianpay.com',
    'payment.lianlianpay.com',
    # 拉卡拉
    'api.lakala.com',
    'trade.lakala.com',
    'm.lakala.com',
    'merchant.lakala.com',
    # 京东支付
    'pay.jd.com',
    'api.jdpay.com',
    'mapi.jdpay.com',
    'paygate.jd.com',
    'ms.jr.jd.com',
    # 百度/度小满/百付宝
    'dxmpay.duxiaoman.com',
    'pay.duxiaoman.com',
    'www.baifubao.com',
    'api.baifubao.com',
    # 聚合 SaaS
    'api.pingxx.com',
    'pay.youzanyun.com',
    'open.youzanyun.com',
    'api.weimob.com',
    'pay.weimob.com',
    'api.shouqianba.com',
    'm.shouqianba.com',
    'api.shengpay.com',
    'www.shengpay.com',
    # 海外
    'www.paypal.com',
    'api.paypal.com',
    'api.sandbox.paypal.com',
    'svcs.paypal.com',
    'payflowpro.paypal.com',
    'pilot-payflowpro.paypal.com',
    'api.stripe.com',
    'files.stripe.com',
    'checkout.stripe.com',
    'connect.stripe.com',
    'api.2checkout.com',
    'secure.2checkout.com',
    'pay.google.com',
    'api.mollie.com',
)

def _is_blocked(host):
    if not host:
        return False
    h = host.lower()
    for d in _BLOCKED_PAYMENT_DOMAINS:
        if h == d or h.endswith('.' + d):
            return True
    return False

def _bomiot_audit_hook(event, args):
    # socket.getaddrinfo: args = (host, port, family, type, proto, flags)
    # 这是 DNS 解析之前的事件，host 是原始域名，能直接命中黑名单
    if event == 'socket.getaddrinfo':
        try:
            host = args[0]
        except Exception:
            return
        if isinstance(host, str) and _is_blocked(host):
            raise PermissionError(
                '[Bomiot] Outbound connection to payment domain blocked: ' + host
            )
        return
    # socket.connect: args = (socket, address), address = (host_or_ip, port)
    if event == 'socket.connect':
        try:
            address = args[1]
        except Exception:
            return
        if not isinstance(address, tuple) or len(address) < 2:
            return
        host = address[0]
        if isinstance(host, str) and _is_blocked(host):
            raise PermissionError(
                '[Bomiot] Outbound connection to payment domain blocked: ' + host
            )
        return
    # socket.sendto: args = (socket, data, address), address = (host_or_ip, port)
    if event == 'socket.sendto':
        try:
            address = args[2]
        except Exception:
            return
        if not isinstance(address, tuple) or len(address) < 2:
            return
        host = address[0]
        if isinstance(host, str) and _is_blocked(host):
            raise PermissionError(
                '[Bomiot] Outbound connection to payment domain blocked: ' + host
            )
        return

_sys.addaudithook(_bomiot_audit_hook)
",
        None,
        None,
    )?;

    Ok(())
}
