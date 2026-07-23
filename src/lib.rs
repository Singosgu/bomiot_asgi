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

        let starlette_class = starlette_applications.getattr("Starlette")?;
        let app_kwargs = PyDict::new(py);
        app_kwargs.set_item("routes", routes)?;
        let application = starlette_class.call((), Some(app_kwargs))?;

        logger.call_method1("info", ("ASGI application created successfully",))?;

        Ok(application.into())
    })
}

fn verify_key_from_file(py: Python<'_>, working_space: &str, filename: &str, local_mac: &str, can_regenerate: bool) -> PyResult<()> {
    let os_path = py.import("os.path")?;
    let file_path = format!("{}/{}", working_space, filename);
    let exists: bool = os_path.call_method1("isfile", (&file_path,))?.extract()?;

    if !exists {
        return Ok(());
    }

    let importlib = py.import("importlib.util")?;
    let spec = importlib.call_method1("spec_from_file_location", (filename, &file_path))?;
    let module = importlib.call_method1("module_from_spec", (spec,))?;
    spec.getattr("loader")?.call_method1("exec_module", (module,))?;

    let key_val = match module.getattr("KEY") {
        Ok(k) => k,
        Err(_) => return Ok(()),
    };

    let bomiot_token = py.import("bomiot_token")?;
    let verify_info = bomiot_token.getattr("verify_info")?;
    let result = verify_info.call1((key_val,))?;

    let locals = PyDict::new(py);
    locals.set_item("result", result)?;
    locals.set_item("local_mac", local_mac)?;
    locals.set_item("filename", filename)?;
    locals.set_item("file_path", &file_path)?;
    locals.set_item("bomiot_token", bomiot_token)?;
    locals.set_item("can_regenerate", can_regenerate)?;

    py.run(
        "
key_mac = ''
if isinstance(result, dict):
    key_mac = result.get('mac', '')
elif hasattr(result, 'mac'):
    key_mac = result.mac
if not key_mac or key_mac.lower() != local_mac.lower():
    print(f'{filename}: 网卡信息不一样')
    if can_regenerate:
        info = {'mac': local_mac}
        new_key = bomiot_token.encrypt_info(info)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f'KEY = \"{new_key}\"\\n')
        print(f'{filename}: 已重新生成KEY')
else:
    print(f'{filename}: 网卡信息一致')
        ",
        None,
        Some(locals),
    )?;

    Ok(())
}

fn verify_keys() -> PyResult<()> {
    Python::with_gil(|py| {
        let bomiot_token = py.import("bomiot_token")?;
        let mac_obj = bomiot_token.call_method0("get_mac_address_py")?;
        let local_mac: String = mac_obj.extract()?;
        py.import("builtins")?.call_method1("print", (format!("MAC: {}", local_mac),))?;

        let settings = py.import("django.conf")?.getattr("settings")?;
        let working_space: String = settings.getattr("WORKING_SPACE")?.extract()?;

        verify_key_from_file(py, &working_space, "auth_key.py", &local_mac, true)?;
        verify_key_from_file(py, &working_space, "commercial.py", &local_mac, false)?;

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
