#![allow(non_local_definitions)]
use pyo3::prelude::*;
use pyo3::types::{PyString, PyList, PyDict};

#[pyclass]
pub struct CustomServerHeaderMiddleware;

#[pymethods]
impl CustomServerHeaderMiddleware {
    #[new]
    fn new() -> Self {
        CustomServerHeaderMiddleware
    }

    fn dispatch(&self, py: Python, request: PyObject, call_next: PyObject) -> PyResult<PyObject> {
        // 同步调用 call_next
        let response = call_next.call1(py, (request,))?;
        // 设置 Server 头
        let response_ref = response.as_ref();
        let headers = response_ref.getattr(py, "headers")?;
        headers.call_method1(py, "__setitem__", (
            PyString::new(py, "Server"),
            PyString::new(py, "Bomiot"),
        ))?;
        Ok(response)
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
fn bomiot_asgi(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CustomServerHeaderMiddleware>()?;
    m.add_function(wrap_pyfunction!(create_asgi_application, m)?)?;
    let application = create_asgi_application(py)?;
    m.add("application", application)?;
    Ok(())
}