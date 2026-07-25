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

        // 定义真实IP中间件
        py.run(
            "
class RealIPMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http':
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
        await self.app(scope, receive, send)
            ",
            None,
            None,
        )?;

        let middleware_class = py.import("starlette.middleware")?.getattr("Middleware")?;
        let real_ip_middleware = py.eval("RealIPMiddleware", None, None)?;
        let middleware_list = PyList::empty(py);
        middleware_list.append(middleware_class.call1((real_ip_middleware,))?)?;

        let starlette_class = starlette_applications.getattr("Starlette")?;
        let app_kwargs = PyDict::new(py);
        app_kwargs.set_item("routes", routes)?;
        app_kwargs.set_item("middleware", middleware_list)?;
        let application = starlette_class.call((), Some(app_kwargs))?;

        logger.call_method1("info", ("ASGI application created successfully",))?;

        Ok(application.into())
    })
}

fn verify_key_from_file(py: Python<'_>, working_space: &str, filename: &str, local_mac_list: &PyAny, can_regenerate: bool) -> PyResult<()> {
    let os_path = py.import("os.path")?;
    let file_path = format!("{}/{}", working_space, filename);
    let exists: bool = os_path.call_method1("isfile", (&file_path,))?.extract()?;

    let builtins = py.import("builtins")?;
    builtins.call_method1("print", (format!("[DEBUG] 文件{}存在: {}", filename, exists),))?;

    if !exists {
        return Ok(());
    }

    let importlib = py.import("importlib.util")?;
    builtins.call_method1("print", (format!("[DEBUG] {} 开始加载模块", filename),))?;
    let spec = importlib.call_method1("spec_from_file_location", (filename, &file_path))?;
    let module = importlib.call_method1("module_from_spec", (spec,))?;
    spec.getattr("loader")?.call_method1("exec_module", (module,))?;
    builtins.call_method1("print", (format!("[DEBUG] {} 模块加载完成", filename),))?;

    let key_val = match module.getattr("KEY") {
        Ok(k) => {
            builtins.call_method1("print", (format!("[DEBUG] {} KEY值: {}", filename, k),))?;
            k
        }
        Err(e) => {
            builtins.call_method1("print", (format!("[DEBUG] {} 没有KEY属性: {}", filename, e),))?;
            return Ok(());
        }
    };

    let bomiot_token = py.import("bomiot_token")?;
    let verify_info = bomiot_token.getattr("verify_info")?;
    builtins.call_method1("print", (format!("[DEBUG] {} 开始调用verify_info", filename),))?;
    let result = match verify_info.call1((key_val,)) {
        Ok(r) => {
            builtins.call_method1("print", (format!("[DEBUG] {} verify_info成功: {}", filename, r),))?;
            r
        }
        Err(e) => {
            builtins.call_method1("print", (format!("[DEBUG] {} verify_info失败: {}", filename, e),))?;
            return Ok(());
        }
    };

    let locals = PyDict::new(py);
    locals.set_item("result", result)?;
    locals.set_item("local_mac_list", local_mac_list)?;
    locals.set_item("filename", filename)?;
    locals.set_item("file_path", &file_path)?;
    locals.set_item("bomiot_token", bomiot_token)?;
    locals.set_item("can_regenerate", can_regenerate)?;

    py.run(
        "
print(f'[DEBUG] 处理文件: {filename}')
print(f'[DEBUG] 文件路径: {file_path}')

stored_mac_str = ''
if isinstance(result, tuple):
    if len(result) > 0:
        stored_mac_str = str(result[0]).strip()
    print(f'[DEBUG] 解密结果: {result}')
    print(f'[DEBUG] key中MAC字符串: {stored_mac_str}')
else:
    print(f'[DEBUG] 解密结果格式不对: {type(result)}')

key_mac_set = {m.strip().upper() for m in stored_mac_str.split(',') if m.strip()}
local_mac_set = {m.strip().upper() for m in local_mac_list if m.strip()}

print(f'[DEBUG] key的MAC集合({len(key_mac_set)}个): {key_mac_set}')
print(f'[DEBUG] 本机MAC集合({len(local_mac_set)}个): {local_mac_set}')

common = key_mac_set & local_mac_set
print(f'[DEBUG] 共同MAC: {common}')

matched = len(common) > 0
print(f'[DEBUG] 比对结果: {matched}')

if matched:
    print(f'{filename}: 网卡信息一致')
else:
    print(f'{filename}: 网卡信息不一样')

print(f'[DEBUG] can_regenerate: {can_regenerate}')
if can_regenerate:
    print(f'[DEBUG] 开始重新生成KEY...')
    try:
        new_key = bomiot_token.encrypt_info()
        print(f'[DEBUG] 新KEY: {new_key}')
        print(f'[DEBUG] 准备写入文件: {file_path}')
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f'KEY = \"{new_key}\"\\n')
        print(f'[DEBUG] 文件写入完成')
        print(f'{filename}: 已重新生成KEY')
    except Exception as e:
        print(f'[DEBUG] 重新生成KEY失败: {e}')
else:
    print(f'[DEBUG] 不允许重新生成')
        ",
        None,
        Some(locals),
    )?;

    Ok(())
}

fn verify_keys() -> PyResult<()> {
    Python::with_gil(|py| {
        py.import("builtins")?.call_method1("print", ("[DEBUG] 开始执行verify_keys",))?;
        let bomiot_token = py.import("bomiot_token")?;
        py.import("builtins")?.call_method1("print", ("[DEBUG] bomiot_token导入成功",))?;
        let mac_list = bomiot_token.call_method0("get_mac_address_py")?;
        py.import("builtins")?.call_method1("print", (format!("[DEBUG] 本机MAC: {:?}", mac_list),))?;

        let settings = py.import("django.conf")?.getattr("settings")?;
        let working_space: String = settings.getattr("WORKING_SPACE")?.extract()?;
        py.import("builtins")?.call_method1("print", (format!("[DEBUG] WORKING_SPACE: {}", working_space),))?;

        verify_key_from_file(py, &working_space, "auth_key.py", mac_list, true)?;
        verify_key_from_file(py, &working_space, "commercial.py", mac_list, false)?;

        py.import("builtins")?.call_method1("print", ("[DEBUG] verify_keys执行完成",))?;
        Ok(())
    })
}

#[pymodule]
fn bomiot_asgi(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_asgi_application, m)?)?;

    let _ = verify_keys();

    let application = create_asgi_application()?;
    m.add("application", application)?;
    Ok(())
}
