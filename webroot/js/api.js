function getMeta(name) {
    const elements = document.getElementsByTagName("meta");
    const m = Array.prototype.slice.call(elements).find( m => m.getAttribute("http-equiv") == name );
    return m ? m.getAttribute("content") : "";
}
function preparePost(uri, form) {
    const xauth = "Authorization";
    const xcsrf = "X-CSRF-Token";
    var headers = {};
    headers[xauth] = getMeta(xauth);
    headers[xcsrf] = getMeta(xcsrf);
    return {
        url: uri, dataType: "json", contentType: "application/json",
        headers: headers,
        data: JSON.stringify(form)
    };
}
function onClickSignUp() {
    const form = {"email": $('#email').val()};
    const body = preparePost("/api/invite", form);
    $.post(body).done( () => {
        alert("Please check your email for an invitation link.");
    }).fail(
        error => alert(error.responseText)
    );
}
function onClickSignIn() {
    const form = {
        "email": $('#email').val(),
        "password": $('#password').val()
    };
    const body = preparePost("/api/login", form);
    $.post(body).done( (data) => {
        if (data.token.length > 0) {
            $('head').append(`<meta http-equiv="Authorization" content="Bearer ${data.token}"/>`);
            $('#popupLogin').modal('toggle');
        } else {
            alert("sorry, unable to login.");
            console.dir(data);
        }
    }).fail(
        error => alert(error.responseText)
    );
}
function onClickJoin() {
    const form = {
        "code": $('#code').val(),
        "password": $('#newPassword').val()
    };
    const body = preparePost("/api/register", form);
    $.post(body).done( () => {
        alert("Success! Please login!");
        window.location = "/";
    }).fail(
        error => alert(error.responseText)
    );
}
function onClickReset() {
    const form = {"email": $('#email').val()};
    const body = preparePost("/api/reset/attempt", form);
    $.post(body).done( () => {
        alert("Please check your email for an password reset link.");
    }).fail(
        error => alert(error.responseText)
    );
}
function onClickConfirmReset() {
    const form = {
        "code": $('#code').val(),
        "password": $('#newPassword').val()
    };
    const body = preparePost("/api/reset/confirm", form);
    $.post(body).done( () => {
        alert("Success! Please login!");
        window.location = "/";
    }).fail(
        error => alert(error.responseText)
    );
}