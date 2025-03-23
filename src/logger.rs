use env_logger::Builder;
use log::LevelFilter;
use std::io::Write;
use log::info;

// Custom logger setup
pub fn setup_logger() {
    let mut builder = Builder::from_default_env();
    
    builder
        .format(|buf, record| {
            // Choose color based on log level
            let level_color = match record.level() {
                log::Level::Error => "\x1B[1;31m", // Bold Red
                log::Level::Warn => "\x1B[1;33m",  // Bold Yellow
                log::Level::Info => "\x1B[1;32m",  // Bold Green
                log::Level::Debug => "\x1B[1;36m", // Bold Cyan
                log::Level::Trace => "\x1B[1;35m", // Bold Magenta
            };
            let reset = "\x1B[0m";
            
            writeln!(
                buf,
                "[{}] {}{}{}{}[{}:{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                level_color,
                record.level(),
                reset,
                " ",
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .filter(None, LevelFilter::Debug)  // Set default level to Debug to see more logs
        .init();
    
    info!("Logger initialized at Debug level");
}