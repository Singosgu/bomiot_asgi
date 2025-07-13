#![allow(non_local_definitions)]
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;

#[pyclass]
struct RustRouter {
    fastapi_app: PyObject,
    flask_app: PyObject,
    django_app: PyObject,
}

#[pymethods]
impl RustRouter {
    #[new]
    fn new(fastapi_app: PyObject, flask_app: PyObject, django_app: PyObject) -> Self {
        RustRouter {
            fastapi_app,
            flask_app,
            django_app,
        }
    }

    fn __call__<'a>(
        &self,
        py: Python<'a>,
        scope: &PyDict,
        receive: PyObject,
        send: PyObject,
    ) -> PyResult<&'a PyAny> {
        let path: &str = scope
            .get_item("path")
            .map_err(|_| pyo3::exceptions::PyKeyError::new_err("path not found"))?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("path not found"))?
            .extract()
            .map_err(|_| pyo3::exceptions::PyTypeError::new_err("path is not a str"))?;
        let target_app = if path.starts_with("/fastapi") {
            &self.fastapi_app
        } else if path.starts_with("/flask") {
            &self.flask_app
        } else {
            &self.django_app
        };
        let target_app = target_app.clone_ref(py);
        let scope = scope.to_object(py);
        let receive = receive.clone_ref(py);
        let send = send.clone_ref(py);

        future_into_py(py, async move {
            Python::with_gil(|py| {
                let awaitable = target_app.call1(py, (scope, receive, send))?;
                pyo3_asyncio::tokio::into_future(awaitable.as_ref(py))
            })?
            .await?;
            Ok(Python::with_gil(|py| py.None()))
        })
    }
}

// All #[pyfunction] and #[pymodule] go after the #[pymethods] impl
#[pyfunction]
fn rust_send(py: Python, event: PyObject, send_obj: PyObject) -> PyResult<PyObject> {
    let event = event.as_ref(py);
    if let Ok(event_dict) = event.downcast::<PyDict>() {
        if let Ok(Some(typ_any)) = event_dict.get_item("type") {
            if let Ok(typ) = typ_any.extract::<&str>() {
                if typ == "http.response.start" {
                    if let Ok(Some(headers_any)) = event_dict.get_item("headers") {
                        if let Ok(headers) = headers_any.downcast::<PyList>() {
                            let server_header = (
                                PyBytes::new(py, b"Server"),
                                PyBytes::new(py, b"Bomiot"),
                            );
                            let _ = headers.insert(0, server_header);
                        }
                    }
                }
            }
        }
    }
    let awaitable = send_obj.call1(py, (event,))?;
    Ok(awaitable)
}

#[pyfunction]
fn create_application() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        // 返回 rust_send 函数
        let rust_send_func = pyo3::wrap_pyfunction!(rust_send, py)?;
        Ok(rust_send_func.into())
    })
}

#[pymodule]
fn bomiot_asgi(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RustRouter>()?;
    m.add_function(wrap_pyfunction!(rust_send, m)?)?;
    m.add_function(wrap_pyfunction!(create_application, m)?)?;
    let application = create_application()?;
    m.add("application", application)?;
    Ok(())
}