fn main() {
    let req = tauri::http::Request::new(vec![]);
    let _h = req.headers();
}
