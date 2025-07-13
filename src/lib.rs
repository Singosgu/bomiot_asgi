use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::wrap_pyfunction;

#[pyclass]
struct CustomServerHeaderMiddleware {
    #[pyo3(get)]
    app: PyObject,
}

#[pymethods]
impl CustomServerHeaderMiddleware {
    #[new]
    fn new(app: PyObject) -> Self {
        Self { app }
    }

    fn __call__(
        &self,
        py: Python,
        scope: PyObject,
        receive: PyObject,
        send: PyObject,
    ) -> PyResult<PyObject> {
        let app = self.app.clone();
        let result = app.call_method1(py, "__call__", (scope, receive, send))?;
        Ok(result)
    }
}

#[pyfunction]
fn create_asgi_application() -> PyResult<PyObject> {
    Python::with_gil(|py| {
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
        let application = starlette_class.call((), Some(app_kwargs))?;

        let middleware_class = py.get_type::<CustomServerHeaderMiddleware>();
        let middleware = middleware_class.call1((application,))?;

        Ok(middleware.into())
    })
}

#[pymodule]
fn bomiot_asgi(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_asgi_application, m)?)?;
    m.add_class::<CustomServerHeaderMiddleware>()?;

    // 直接在GIL作用域内创建application，避免闭包捕获m
    if let Ok(application) = create_asgi_application() {
        m.add("application", application).ok();
    }

    Ok(())
}