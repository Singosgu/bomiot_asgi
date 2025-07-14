#![allow(non_local_definitions)]
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::wrap_pyfunction;

#[pyfunction]
fn create_asgi_application() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        // 导入 Python 依赖
        let django_asgi = py.import("django.core.asgi")?;
        let starlette_applications = py.import("starlette.applications")?;
        let starlette_routing = py.import("starlette.routing")?;
        let wsgi_middleware = py.import("starlette.middleware.wsgi")?.getattr("WSGIMiddleware")?;
        let importlib = py.import("importlib")?;
        let django_settings = py.import("django.conf")?.getattr("settings")?;
        let starlette_base_middleware = py.import("starlette.middleware.base")?;
        let starlette_requests = py.import("starlette.requests")?;

        // 获取 Django ASGI 应用
        let get_asgi_application = django_asgi.getattr("get_asgi_application")?;
        let http_application = get_asgi_application.call0()?;

        // 获取项目名称
        let project_name = django_settings.getattr("PROJECT_NAME")?.extract::<String>()?;

        // 动态导入 FastAPI 应用
        let fastapi_app = {
            let fastapi_module_path = format!("{}.fastapi_app.main", project_name);
            let fastapi_module = importlib.call_method1("import_module", (fastapi_module_path,))?;
            fastapi_module.getattr("fastapi_app")?
        };

        // 动态导入 Flask 应用
        let flask_app = {
            let flask_module_path = format!("{}.flask_app.main", project_name);
            let flask_module = importlib.call_method1("import_module", (flask_module_path,))?;
            flask_module.getattr("flask_app")?
        };

        // 创建路由列表
        let routes = PyList::empty(py);
        let mount_class = starlette_routing.getattr("Mount")?;
        let fastapi_mount = mount_class.call1(("/fastapi", fastapi_app))?;
        routes.append(fastapi_mount)?;
        let flask_wsgi = wsgi_middleware.call1((flask_app,))?;
        let flask_mount = mount_class.call1(("/flask", flask_wsgi))?;
        routes.append(flask_mount)?;
        let django_mount = mount_class.call1(("/", http_application))?;
        routes.append(django_mount)?;

        // 创建 Starlette 应用
        let starlette_class = starlette_applications.getattr("Starlette")?;
        let app_kwargs = PyDict::new(py);
        app_kwargs.set_item("routes", routes)?;
        let application = starlette_class.call((), Some(app_kwargs))?;

        // 定义自定义中间件
        let _base_middleware = starlette_base_middleware.getattr("BaseHTTPMiddleware")?;
        let _requests_mod = starlette_requests;
        let middleware_code = r#"
class CustomServerHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Server"] = "Bomiot"
        return response
"#;
        py.run(middleware_code, None, None)?;
        let custom_middleware = py.eval("CustomServerHeaderMiddleware", None, None)?;
        application.call_method1("add_middleware", (custom_middleware,))?;

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