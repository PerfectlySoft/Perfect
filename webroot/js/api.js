function getMeta(name) {
    const elements = document.getElementsByTagName("meta");
    const m = Array.prototype.slice.call(elements).find( m => m.getAttribute("http-equiv") == name );
    return m ? m.getAttribute("content") : "";
}
function getCsrfToken() {
    return getMeta("X-CSRF-Token");
}
function getAuthorization() {
    return getMeta("Authorization");
}
function onClickSignUp() {
    let csrf = getCsrfToken();
    let auth = getAuthorization();
    console.log("csrf", csrf, "auth", auth);
}