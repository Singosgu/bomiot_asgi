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
import importlib.util
import bomiot_token

def do_verify():
    from django.conf import settings
    working_space = settings.WORKING_SPACE
    local_mac_list = bomiot_token.get_mac_address_py()
    commercial_ok = True

    for filename, can_regenerate in [('auth_key.py', True), ('commercial.py', False)]:
        file_path = os.path.join(working_space, filename)
        if not os.path.isfile(file_path):
            continue
        try:
            spec = importlib.util.spec_from_file_location(filename, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if not hasattr(module, 'KEY'):
                continue
            key_val = module.KEY
            result = bomiot_token.verify_info(key_val)
            if isinstance(result, tuple) and len(result) > 0:
                stored_mac_str = str(result[0]).strip()
            else:
                continue
            key_mac_set = {m.strip().upper() for m in stored_mac_str.split(',') if m.strip()}
            local_mac_set = {m.strip().upper() for m in local_mac_list if m.strip()}
            common = key_mac_set & local_mac_set
            matched = len(common) > 0
            if matched:
                print(f'{filename}: 网卡信息一致')
            else:
                print(f'{filename}: 网卡信息不一样')
                if can_regenerate:
                    try:
                        new_key = bomiot_token.encrypt_info()
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(f'KEY = \"{new_key}\"\\n')
                        print(f'{filename}: 已重新生成KEY')
                    except Exception as e:
                        print(f'{filename}: 重新生成KEY失败: {e}')
                else:
                    commercial_ok = False
        except Exception as e:
            print(f'{filename}: 验证异常: {e}')
            if not can_regenerate:
                commercial_ok = False
    return commercial_ok

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

        commercial_ok = do_verify()
        if not commercial_ok:
            from starlette.responses import PlainTextResponse
            response = PlainTextResponse('Forbidden', status_code=403)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
            ",
            None,
            None,
        )?;

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
