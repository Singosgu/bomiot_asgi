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
import ipaddress
import importlib.util
import bomiot_token

def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local

def parse_key_file(file_path):
    if not os.path.isfile(file_path):
        return None
    try:
        spec = importlib.util.spec_from_file_location(os.path.basename(file_path), file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not hasattr(module, 'KEY'):
            return None
        result = bomiot_token.verify_info(module.KEY)
        if isinstance(result, tuple) and len(result) >= 2:
            mac_str = str(result[0]).strip()
            ts_str = str(result[1]).strip()
            try:
                timestamp = int(ts_str)
            except (ValueError, TypeError):
                timestamp = 0
            return (mac_str, timestamp)
        return None
    except Exception as e:
        print(f'解析{os.path.basename(file_path)}失败: {e}')
        return None

def mac_matches(stored_mac_str, local_mac_list):
    key_mac_set = {m.strip().upper() for m in stored_mac_str.split(',') if m.strip()}
    local_mac_set = {m.strip().upper() for m in local_mac_list if m.strip()}
    return len(key_mac_set & local_mac_set) > 0

def regenerate_auth_key(file_path):
    try:
        new_key = bomiot_token.encrypt_info()
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f'KEY = \"{new_key}\"\\n')
        print(f'auth_key.py: 已重新生成KEY')
        return True
    except Exception as e:
        print(f'auth_key.py: 重新生成KEY失败: {e}')
        return False

def init_auth_key():
    from django.conf import settings
    working_space = settings.WORKING_SPACE
    local_mac_list = bomiot_token.get_mac_address_py()
    auth_key_path = os.path.join(working_space, 'auth_key.py')
    need_regenerate = False
    if os.path.isfile(auth_key_path):
        auth_data = parse_key_file(auth_key_path)
        if auth_data is not None:
            stored_mac_str, _ = auth_data
            if not mac_matches(stored_mac_str, local_mac_list):
                need_regenerate = True
        else:
            need_regenerate = True
    else:
        need_regenerate = True
    if need_regenerate:
        regenerate_auth_key(auth_key_path)

class VerifyMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        headers_dict = dict(scope.get('headers', []))
        xff = headers_dict.get(b'x-forwarded-for', b'').decode()
        xri = headers_dict.get(b'x-real-ip', b'').decode()
        if xff:
            real_ip = xff.split(',')[0].strip()
        elif xri:
            real_ip = xri.strip()
        else:
            real_ip = scope.get('client', ('', 0))[0]
        client = scope.get('client')
        if client:
            scope['client'] = (real_ip, client[1])
        else:
            scope['client'] = (real_ip, 0)
        if b'x-real-ip' not in headers_dict:
            scope['headers'].append((b'x-real-ip', real_ip.encode()))

        print(f'[访问] {scope.get(\"method\", \"\")} {scope.get(\"path\", \"\")} -> {real_ip}')

        from django.conf import settings
        working_space = settings.WORKING_SPACE
        local_mac_list = bomiot_token.get_mac_address_py()
        now = int(time.time())

        commercial_path = os.path.join(working_space, 'commercial.py')

        if os.path.isfile(commercial_path):
            commercial_data = parse_key_file(commercial_path)
            if commercial_data is not None:
                stored_mac_str, commercial_ts = commercial_data
                if mac_matches(stored_mac_str, local_mac_list):
                    if commercial_ts > now:
                        await self.app(scope, receive, send)
                        return
                    else:
                        if is_private_ip(real_ip):
                            await self.app(scope, receive, send)
                            return
                        else:
                            from starlette.responses import PlainTextResponse
                            print(f'订阅已过期，公网IP被拒绝: {real_ip} {scope.get(\"method\", \"\")} {scope.get(\"path\", \"\")}')
                            response = PlainTextResponse('Forbidden', status_code=403)
                            await response(scope, receive, send)
                            return
                else:
                    print('Commercial Key MAC地址不匹配，只能内网访问，需要外网访问请重新订阅')
            else:
                print('Commercial Key MAC地址不匹配，只能内网访问，需要外网访问请重新订阅')
        else:
            pass

        if is_private_ip(real_ip):
            await self.app(scope, receive, send)
            return
        else:
            from starlette.responses import PlainTextResponse
            print(f'免费模式仅允许内网IP访问，公网IP被拒绝: {real_ip} {scope.get(\"method\", \"\")} {scope.get(\"path\", \"\")}')
            response = PlainTextResponse('Forbidden', status_code=403)
            await response(scope, receive, send)
            return
            ",
            None,
            None,
        )?;

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
