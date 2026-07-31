use crate::pe::PeFile;

pub trait UnpackerPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn is_64bit(&self) -> bool;
    fn can_process(&self, pe: &PeFile) -> bool;
    fn unpack(&self, pe: &PeFile, output_path: &str) -> Result<(), String>;
}

pub mod variant10_x86;
pub mod variant20_x86;
pub mod variant21_x86;
pub mod variant30_x64;
pub mod variant30_x86;
pub mod variant31_x64;
pub mod variant31_x86;

pub struct UnpackerRegistry {
    plugins: Vec<Box<dyn UnpackerPlugin>>,
}

impl UnpackerRegistry {
    pub fn new() -> Self {
        let mut registry = Self { plugins: Vec::new() };
        registry.register(Box::new(variant10_x86::Variant10x86));
        registry.register(Box::new(variant20_x86::Variant20x86));
        registry.register(Box::new(variant21_x86::Variant21x86));
        registry.register(Box::new(variant30_x86::Variant30x86));
        registry.register(Box::new(variant30_x64::Variant30x64));
        registry.register(Box::new(variant31_x86::Variant31x86));
        registry.register(Box::new(variant31_x64::Variant31x64));
        registry
    }

    pub fn register(&mut self, plugin: Box<dyn UnpackerPlugin>) {
        self.plugins.push(plugin);
    }

    pub fn find_unpacker<'a>(&'a self, pe: &PeFile) -> Option<&'a dyn UnpackerPlugin> {
        for plugin in &self.plugins {
            if plugin.can_process(pe) {
                return Some(plugin.as_ref());
            }
        }
        None
    }

    pub fn list_plugins(&self) -> Vec<(&'static str, &'static str, bool)> {
        self.plugins.iter().map(|p| (p.name(), p.version(), p.is_64bit())).collect()
    }
}
