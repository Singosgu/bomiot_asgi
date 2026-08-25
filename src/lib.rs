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

def check_auth_via_bomiot_server(community_key, sponsor_key):
    '''向 127.0.0.1:8000 发送认证请求，返回 (success, expired_timestamp)'''
    import requests
    try:
        resp = requests.post(
            'http://127.0.0.1:8000/auth/',
            json={'COMMUNITY_KEY': community_key, 'SPONSOR_KEY': sponsor_key},
            timeout=10
        )
        data = resp.json()
        expired = data.get('expired', 0)
        try:
            expired = int(expired)
        except (ValueError, TypeError):
            expired = 0
        return (True, expired)
    except Exception:
        return (False, 0)

# 模块级缓存：auth_key 的路径与解析后的原始 keys，
# 供 /projectlist 触发的后台 POST 复用，避免每次请求读磁盘
_CACHED_AUTH_KEY_PATH = None
_CACHED_AUTH_RAW_KEYS = None  # (community_key, sponsor_key) or None

def _fire_auth_post_background(timeout=2):
    '''后台线程发一次 POST，完全不阻塞调用方，失败全吞'''
    try:
        import requests as _req
        if _CACHED_AUTH_RAW_KEYS is None:
            return
        community_key, sponsor_key = _CACHED_AUTH_RAW_KEYS
        _req.post(
            'http://127.0.0.1:8000/auth/',
            json={'COMMUNITY_KEY': community_key, 'SPONSOR_KEY': sponsor_key},
            timeout=timeout
        )
    except Exception:
        pass

def fire_auth_post_on_projectlist(auth_key_path_hint):
    '''访问 /projectlist 前缀路径时触发一次 POST（后台线程，零等待）'''
    global _CACHED_AUTH_RAW_KEYS, _CACHED_AUTH_KEY_PATH
    try:
        import threading
        # 记录路径 hint（IS_LAN=false 启动时不跑 LAN 逻辑，可能没缓存）
        if _CACHED_AUTH_KEY_PATH is None and auth_key_path_hint:
            _CACHED_AUTH_KEY_PATH = auth_key_path_hint
        # 缓存未命中 → 尝试解析一次文件（之后不再读）
        if _CACHED_AUTH_RAW_KEYS is None:
            if _CACHED_AUTH_KEY_PATH and os.path.isfile(_CACHED_AUTH_KEY_PATH):
                k = parse_key_file(_CACHED_AUTH_KEY_PATH)
                if k is not None:
                    _CACHED_AUTH_RAW_KEYS = k
        if _CACHED_AUTH_RAW_KEYS is None:
            return
        t = threading.Thread(target=_fire_auth_post_background, args=(2,), daemon=True)
        t.start()
    except Exception:
        pass

def regenerate_auth_key(file_path):
    try:
        community_key, sponsor_key = bomiot_token.encrypt_info()
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f'COMMUNITY_KEY = \"{community_key}\"\\n')
            f.write(f'SPONSOR_KEY = \"{sponsor_key}\"\\n')
        return True
    except Exception as e:
        return False

def detect_nuitka_and_set_is_lan():
    '''检测是否为 Nuitka 打包环境，设置 IS_LAN 环境变量'''
    is_nuitka = False
    
    # 方法1：检查 sys.compiled 属性 (Nuitka 会设置)
    import sys
    if getattr(sys, 'compiled', False):
        is_nuitka = True
    
    # 方法2：检查 sys.modules 中的模块是否有 __compiled__
    if not is_nuitka:
        for name, mod in list(sys.modules.items())[:50]:
            if hasattr(mod, '__compiled__'):
                is_nuitka = True
                break
    
    # 方法3：检查 Nuitka 环境变量
    if os.environ.get('NUITKA_ONEFILE') == '1':
        is_nuitka = True
    
    # 设置 IS_LAN 环境变量
    if is_nuitka:
        os.environ['IS_LAN'] = 'true'
    else:
        os.environ['IS_LAN'] = 'false'

def init_auth_key():
    detect_nuitka_and_set_is_lan()

    from django.conf import settings
    working_space = settings.WORKING_SPACE
    auth_key_path = os.path.join(working_space, 'auth_key.py')
    # 写一份全局缓存（供 /projectlist 触发的后台 POST 使用）
    global _CACHED_AUTH_KEY_PATH, _CACHED_AUTH_RAW_KEYS
    _CACHED_AUTH_KEY_PATH = auth_key_path
    # 启动时发送一次 bomiot.com 认证请求，设置 AUTHED
    is_lan = os.environ.get('IS_LAN', 'false') == 'true'
    if not is_lan:
        os.environ['AUTHED'] = 'true'
        # IS_LAN=false：顺手把已有 auth_key.py 缓存一下 /projectlist 要用（不发启动 POST）
        if os.path.isfile(auth_key_path):
            k = parse_key_file(auth_key_path)
            if k is not None:
                _CACHED_AUTH_RAW_KEYS = k
        return

    raw_keys = None
    if os.path.isfile(auth_key_path):
        raw_keys = parse_key_file(auth_key_path)   # 单次 import：取原始 key 字符串 + 校验解密

    if raw_keys is None:
        regenerate_auth_key(auth_key_path)          # 解密失败/文件不存在 → 重生
        if os.path.isfile(auth_key_path):
            raw_keys = parse_key_file(auth_key_path)  # 重生后再解析一次（解密+取原始）

    if raw_keys is not None:
        _CACHED_AUTH_RAW_KEYS = raw_keys  # 缓存，供 /projectlist 分支使用
        community_key, sponsor_key = raw_keys
        ok, expired_ts = check_auth_via_bomiot_server(community_key, sponsor_key)
        if ok:
            now_ts = int(time.time())
            if expired_ts > now_ts:
                os.environ['AUTHED'] = 'true'
            else:
                os.environ['AUTHED'] = 'false'
        else:
            os.environ['AUTHED'] = 'true'
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

        # /projectlist 前缀：放行前顺手发一次后台 POST（零等待，失败全吞）
        if path.startswith('/projectlist'):
            fire_auth_post_on_projectlist(None)
            await self.app(scope, receive, send)
            return

        if path == '/' or path == '/favicon.ico' or any(path.startswith(prefix) for prefix in ('/css/', '/js/', '/assets/', '/statics/', '/fonts/', '/icons/', '/static/', '/media/', '/md/')):
            await self.app(scope, receive, send)
            return

        if os.environ.get('IS_LAN', 'false') != 'true':
            await self.app(scope, receive, send)
            return

        if os.environ.get('AUTHED', 'false') == 'true':
            await self.app(scope, receive, send)
            return

        from starlette.responses import JSONResponse
        response = JSONResponse({'detail': 'Sponsorship has expired'}, status_code=200)
        await response(scope, receive, send)
    "
    , None, None)?;

        py.run("init_auth_key()", None, None)?;

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

    let application = create_asgi_application()?;
    m.add("application", application)?;
    Ok(())
}
