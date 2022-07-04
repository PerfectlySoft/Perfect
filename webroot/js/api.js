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
    let email = $('#email').val();
    $.post({
        url: "/api/invite",
        dataType: "json",
        contentType: "application/json",
        headers: {
            "X-CSRF-Token": csrf
        },
        data: JSON.stringify({
            "email": email
        })
    }).done( () => {
        alert("Please check your email for an invitation link.");
    }).fail(
        error => alert(error.responseText)
    );
}
function onClickJoin() {
    let csrf = getCsrfToken();
    let code = $('#code').val();
    let password = $('#newPassword').val();
    $.post({
        url: "/api/register",
        dataType: "json",
        contentType: "application/json",
        headers: {
            "X-CSRF-Token": csrf
        },
        data: JSON.stringify({
            "code": code,
            "password": password
        })
    }).done( () => {
        alert("Success! Please login!");
        window.location = "/";
    }).fail(
        error => alert(error.responseText)
    );
}