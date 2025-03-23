use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::Error;
use log::{info, warn, error};
use std::future::{ready, Ready, Future};
use std::pin::Pin;
use std::rc::Rc;

// Logger middleware to log all requests and responses
pub struct RequestLogger;

impl<S, B> Transform<S, ServiceRequest> for RequestLogger
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestLoggerMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestLoggerMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct RequestLoggerMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for RequestLoggerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().clone();
        let path = req.path().to_owned();
        let client_ip = req.connection_info().realip_remote_addr()
            .map(|s| s.to_owned())
            .unwrap_or_else(|| String::from("unknown"));
        
        info!(
            "→ Request: \x1B[1;34m{} {}\x1B[0m from IP: {}",
            method, path, client_ip
        );
        
        let service = self.service.clone();
        
        Box::pin(async move {
            let start = std::time::Instant::now();
            let res = service.call(req).await?;
            let elapsed = start.elapsed();
            
            let status = res.status();
            
            if status.is_success() {
                info!(
                    "← Response: \x1B[1;32m{}\x1B[0m for {} {} completed in {:.2?}",
                    status, method, path, elapsed
                );
            } else if status.is_client_error() {
                warn!(
                    "← Response: \x1B[1;33m{}\x1B[0m for {} {} completed in {:.2?}",
                    status, method, path, elapsed
                );
            } else {
                error!(
                    "← Response: \x1B[1;31m{}\x1B[0m for {} {} completed in {:.2?}",
                    status, method, path, elapsed
                );
            }
            
            Ok(res)
        })
    }
}