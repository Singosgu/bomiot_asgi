#![allow(non_local_definitions)]
use pyo3::prelude::*;
use pyo3::types::{PyString, PyDict, PyList, PyTuple};
use pyo3::PyCell;

#[pyclass]
pub struct CustomServerHeaderMiddleware {
    app: PyObject,
}

#[pymethods]
impl CustomServerHeaderMiddleware {
    #[new]
    fn new(app: PyObject) -> Self {
        CustomServerHeaderMiddleware { app }
    }

    fn __call__(
        &self,
        py: Python,
        scope: PyObject,
        receive: PyObject,
        send: PyObject,
    ) -> PyResult<PyObject> {
        let send_wrapper = PyCell::new(py, SendWrapper { send: send.clone_ref(py) })?.to_object(py);
        let app = self.app.clone_ref(py);
        app.call1(py, (scope, receive, send_wrapper))
    }
}

#[pyclass]
struct SendWrapper {
    send: PyObject,
}

#[pymethods]
impl SendWrapper {
    fn __call__(&self, py: Python, message: PyObject) -> PyResult<PyObject> {
        let msg = message.as_ref(py);
        if let Ok(dict) = msg.downcast::<PyDict>() {
            if let Some(msg_type) = dict.get_item("type")? {
                if msg_type.eq(PyString::new(py, "http.response.start"))? {
                    if let Some(headers) = dict.get_item("headers")? {
                        if let Ok(headers_list) = headers.downcast::<PyList>() {
                            let mut found = false;
                            for (idx, item) in headers_list.iter().enumerate() {
                                if let Ok(pair) = item.downcast::<PyTuple>() {
                                    let name_any = pair.get_item(0)?;
                                    if let Ok(name) = name_any.extract::<&[u8]>() {
                                        if name.eq_ignore_ascii_case(b"server") {
                                            let new_pair = PyTuple::new(py, &[name_any, PyString::new(py, "Bomiot")]);
                                            headers_list.set_item(idx, new_pair)?;
                                            found = true;
                                            break;
                                        }
                                    }
                                }
                            }
                            if !found {
                                let new_pair = PyTuple::new(py, &[PyString::new(py, "server"), PyString::new(py, "Bomiot")]);
                                headers_list.append(new_pair)?;
                            }
                        }
                    }
                }
            }
        }
        self.send.call1(py, (message,))
    }
}

#[pyfunction]
fn create_asgi_application(py: Python) -> PyResult<PyObject> {
    // 导入 Python 依赖
    let django_asgi = py.import("django.core.asgi")?;
    let starlette_applications = py.import("starlette.applications")?;
    let starlette_routing = py.import("starlette.routing")?;
    let wsgi_middleware = py.import("starlette.middleware.wsgi")?.getattr("WSGIMiddleware")?;
    let importlib = py.import("importlib")?;
    let django_settings = py.import("django.conf")?.getattr("settings")?;

    let get_asgi_application = django_asgi.getattr("get_asgi_application")?;
    let http_application = get_asgi_application.call0()?;

    let project_name = django_settings.getattr("PROJECT_NAME")?.extract::<String>()?;

    let fastapi_app = {
        let fastapi_module_path = format!("{}.fastapi_app.main", project_name);
        let fastapi_module = importlib.call_method1("import_module", (fastapi_module_path,))?;
        fastapi_module.getattr("fastapi_app")?
    };

    let flask_app = {
        let flask_module_path = format!("{}.flask_app.main", project_name);
        let flask_module = importlib.call_method1("import_module", (flask_module_path,))?;
        flask_module.getattr("flask_app")?
    };

    let routes = PyList::empty(py);
    let mount_class = starlette_routing.getattr("Mount")?;
    let fastapi_mount = mount_class.call1(("/fastapi", fastapi_app))?;
    routes.append(fastapi_mount)?;
    let flask_wsgi = wsgi_middleware.call1((flask_app,))?;
    let flask_mount = mount_class.call1(("/flask", flask_wsgi))?;
    routes.append(flask_mount)?;
    let django_mount = mount_class.call1(("/", http_application))?;
    routes.append(django_mount)?;

    let starlette_class = starlette_applications.getattr("Starlette")?;
    let app_kwargs = PyDict::new(py);
    app_kwargs.set_item("routes", routes)?;
    let application = starlette_class.call((), Some(&app_kwargs))?;

    let middleware_class = py.get_type::<CustomServerHeaderMiddleware>();
    application.call_method1("add_middleware", (middleware_class,))?;

    Ok(application.into())
}

#[pymodule]
fn bomiot_asgi(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<CustomServerHeaderMiddleware>()?;
    m.add_function(wrap_pyfunction!(create_asgi_application, m)?)?;
    let application = create_asgi_application(py)?;
    m.add("application", application)?;
    Ok(())
}