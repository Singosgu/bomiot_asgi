use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::wrap_pyfunction;

/// 创建完整的 Starlette ASGI 应用
#[pyfunction]
fn create_asgi_application() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        // 导入必要的 Python 模块
        let django_asgi = py.import("django.core.asgi")?;
        let starlette_applications = py.import("starlette.applications")?;
        let starlette_routing = py.import("starlette.routing")?;
        let headers_mod = py.import("headers")?;
        let server_header_middleware = headers_mod.getattr("ServerHeaderMiddleware")?;
        
        // 获取 Django ASGI 应用
        let get_asgi_application = django_asgi.getattr("get_asgi_application")?;
        let http_application = get_asgi_application.call0()?;
        
        // 创建路由列表
        let routes = PyList::empty(py);
        
        let mount_class = starlette_routing.getattr("Mount")?;
                
        // 添加 Django 路由 - 使用正确的Mount构造函数
        let django_mount = mount_class.call1(("/", http_application))?;
        routes.append(django_mount)?;

        // 创建 Starlette 应用
        let starlette_class = starlette_applications.getattr("Starlette")?;
        let app_kwargs = PyDict::new(py);
        app_kwargs.set_item("routes", routes)?;
        let application = starlette_class.call((), Some(app_kwargs))?;

        // 添加 ServerHeaderMiddleware 中间件
        application.call_method1("add_middleware", (server_header_middleware,))?;
        
        Ok(application.into())
    })
}

/// 初始化 Rust 模块
#[pymodule]
fn bomiot_asgi(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_asgi_application, m)?)?;
    
    // 直接创建 application 变量，供 uvicorn 使用
    let application = create_asgi_application()?;
    m.add("application", application)?;
    
    Ok(())
}