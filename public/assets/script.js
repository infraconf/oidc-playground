window.onload = () => {
    const idTokenCodeDOM = document.querySelector('.code-preview.idtoken code');
    const userInfoCodeDOM = document.querySelector('.code-preview.userinfo code');
    const scopes = DATA.params.scope.split(',');
    const generateToken = () => {
        const selectedOptions = Array.from(document.querySelectorAll('.option-checkbox:checked')).map(n => n.name);
        const selectedUser = document.querySelector('.user-option-radio:checked');
        const userID = selectedUser.dataset.userid;
        const userData = DATA.users.find(user => user.id === userID);

        const resp = {
            idToken: [
                { k: "iss", v: "xxxxxxxxxxxxxx" },
                { k: "sub", v: "xxxxxxxxxxxxxx" },
                { k: "aud", v: DATA.params.client_id },
                { k: "exp", v: "1234567890" },
                { k: "iat", v: "1234567890" },
                { k: "auth_time", v: "1234567890" },
                { k: "c_hash", v: "xxxxxxxxxxxxxx" },
                { k: "at_hash", v: "xxxxxxxxxxxxxx" },
            ],
            userInfo: [
                { k: "sub", v: "xxxxxxxxxxxxxx" },
            ],
        };

        const push = (claim) => {
            if (selectedOptions.includes('full-id-token')) {
                resp.idToken.push(claim);
            }
            resp.userInfo.push(claim);
        };

        if (DATA.params.nonce != "") {
            resp.idToken.push({ k: "nonce", v: DATA.params.nonce });
        }

        if (userData != undefined) {
            const customClaims = userData.custom_claims ?? {};

            if (scopes.includes('email')) {
                push({ k: "email", v: userData.claims.email });
                push({ k: "email_verified", v: true , raw: true });
            }
            
            if (scopes.includes('profile')) {
                push({ k: "name", v: userData.name });
                push({ k: "given_name", v: userData.name });
                push({ k: "preferred_username", v: userData.id });
                push({ k: "nickname", v: userData.id });
            }

            if (scopes.includes('groups')) {
                push({ k: "groups", v: '[\n' + userData.claims.groups.map(g => {
                    return '        "' + g + '"';
                }).join(',\n') + '\n    ]', raw: true });
            }

            scopes.forEach(scope => {
                const claim = customClaims[scope];
                if (claim != undefined) {
                    for (const [key, value] of Object.entries(claim)) {
                        push({ k: key, v: value });
                    }
                }
            });
        }
        return resp;
    };
    const generatePreview = () => {
        const previews = {
            userInfo: [],
            idToken: [], 
        };

        if (DATA.error_message != "") {
            idToken.push({ k: "error", v: DATA.error_message});
            userInfo.push({ k: "error", v: DATA.error_message});
        } else {
            const { idToken, userInfo } = generateToken();
            previews.idToken = idToken;
            previews.userInfo = userInfo;
        }

        const print = (claims) => {
            return '{\n' + claims.map(claim => {
                if (claim.raw) {
                    return `    <span class="token-key">"${claim.k}"</span>: ${claim.v}`;
                }
                return `    <span class="token-key">"${claim.k}"</span>: "${claim.v}"`;
            }).join(',\n') +'\n}'
        };

        idTokenCodeDOM.innerHTML = print(previews.idToken);
        userInfoCodeDOM.innerHTML = print(previews.userInfo);
    };
    const submit = () => {
        const optionParameter = Array.from(document.querySelectorAll('.option-checkbox:checked')).map(n => n.name).join(',');

        const selectedUser = document.querySelector('.user-option-radio:checked');
        const userID = selectedUser.dataset.userid;
        const nextURL = new URL(window.location.href);
        nextURL.searchParams.set('target_user', userID);

        if (optionParameter !== '') {
            nextURL.searchParams.set('options', optionParameter);
        } else {
            nextURL.searchParams.delete('options');
        }

        window.location.href = nextURL.toString();
    };

    document.querySelectorAll('.user-option-radio').forEach((elem) => {
        elem.addEventListener('click', generatePreview);
    });
    document.querySelectorAll('.option-checkbox').forEach((elem) => {
        elem.addEventListener('click', generatePreview);
    });

    const submitButton = document.querySelector('#submit');
    const cancelButton = document.querySelector('#cancel');

    cancelButton.addEventListener('click', () => {
        window.history.back();
    });

    if (DATA.error_message == "") {
        submitButton.addEventListener('click', submit);
    } else {
        submitButton.classList.add('not-usable');
        submitButton.classList.remove('button-primary');
    }

    generatePreview();
};
