window.onload = () => {
    const codeBody = document.querySelector('.code-preview code');
    const scopes = DATA.Params.scope.split(',');
    const generatePreview = () => {
        const args = [
            { k: "iss", v: "xxxxxxxxxxxxxx" },
            { k: "sub", v: "xxxxxxxxxxxxxx" },
            { k: "aud", v: DATA.Params.client_id },
            { k: "exp", v: "1234567890" },
            { k: "iat", v: "1234567890" },
            { k: "auth_time", v: "1234567890" },
        ];

        const selectedUser = document.querySelector('.user-option-radio:checked');
        const userID = selectedUser.dataset.userid;
        const userData = DATA.Users.find(user => user.id === userID);

        if (DATA.Params.nonce != "") {
            args.push({ k: "nonce", v: DATA.Params.nonce });
        }

        if (userData != undefined) {
            if (scopes.includes('email')) {
                args.push({ k: "email", v: userData.claims.email });
                args.push({ k: "email_verified", v: true , raw: true });
            }
            
            if (scopes.includes('profile')) {
                args.push({ k: "name", v: userData.name });
                args.push({ k: "given_name", v: userData.name });
                args.push({ k: "preferred_username", v: userData.id });
                args.push({ k: "nickname", v: userData.id });
                args.push({ k: "groups", v: '[\n' + userData.claims.groups.map(g => {
                    return '        "' + g + '"';
                }).join(',\n') + '\n    ]', raw: true });
            }

            scopes.forEach(scope => {
                const claim = userData.custom_claims[scope];
                if (claim != undefined) {
                    for (const [key, value] of Object.entries(claim)) {
                        args.push({ k: key, v: value });
                    }
                }
            });
        }

        codeBody.innerHTML = '{\n' + args.map(arg => {
            if (arg.raw) {
                return '    <span class="token-key">"'+ arg.k +'"</span>: '+ arg.v +'';
            }
            return '    <span class="token-key">"'+ arg.k +'"</span>: "'+ arg.v +'"';
        }).join(',\n') +'\n}';
    };

    document.querySelectorAll('.user-option-radio').forEach((elem) => {
        elem.addEventListener('click', generatePreview);
    })

    generatePreview();
};