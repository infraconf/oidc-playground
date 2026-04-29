window.onload = () => {
    const codeBody = document.querySelector('.code-preview code');
    const scopes = DATA.params.scope.split(',');
    const generateToken = () => {
        const args = [
            { k: "iss", v: "xxxxxxxxxxxxxx" },
            { k: "sub", v: "xxxxxxxxxxxxxx" },
            { k: "aud", v: DATA.params.client_id },
            { k: "exp", v: "1234567890" },
            { k: "iat", v: "1234567890" },
            { k: "auth_time", v: "1234567890" },
        ];

        const selectedUser = document.querySelector('.user-option-radio:checked');
        const userID = selectedUser.dataset.userid;
        const userData = DATA.users.find(user => user.id === userID);

        if (DATA.params.nonce != "") {
            args.push({ k: "nonce", v: DATA.params.nonce });
        }

        if (userData != undefined) {
            const customClaims = userData.custom_claims ?? {};

            if (scopes.includes('email')) {
                args.push({ k: "email", v: userData.claims.email });
                args.push({ k: "email_verified", v: true , raw: true });
            }
            
            if (scopes.includes('profile')) {
                args.push({ k: "name", v: userData.name });
                args.push({ k: "given_name", v: userData.name });
                args.push({ k: "preferred_username", v: userData.id });
                args.push({ k: "nickname", v: userData.id });
            }

            if (scopes.includes('groups')) {
                args.push({ k: "groups", v: '[\n' + userData.claims.groups.map(g => {
                    return '        "' + g + '"';
                }).join(',\n') + '\n    ]', raw: true });
            }

            scopes.forEach(scope => {
                const claim = customClaims[scope];
                if (claim != undefined) {
                    for (const [key, value] of Object.entries(claim)) {
                        args.push({ k: key, v: value });
                    }
                }
            });
        }
        return args;
    };
    const generatePreview = () => {
        let args = [];

        if (DATA.error_message != "") {
            args.push({ k: "error", v: DATA.error_message});
        } else {
            args = generateToken();
        }

        codeBody.innerHTML = '{\n' + args.map(arg => {
            if (arg.raw) {
                return `    <span class="token-key">"${arg.k}"</span>: ${arg.v}`;
            }
            return `    <span class="token-key">"${arg.k}"</span>: "${arg.v}"`;
        }).join(',\n') +'\n}';
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
