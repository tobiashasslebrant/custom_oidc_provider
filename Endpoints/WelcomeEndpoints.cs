namespace CustomOidcProvider.Endpoints;

public static class WelcomeEndpoints
{
    public static IEndpointRouteBuilder MapWelcomeEndpoints(this IEndpointRouteBuilder app, string issuer)
    {
        app.MapGet("/", () => Results.Content($$"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <title>Custom OIDC Provider</title>
                <style>
                    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
                    body {
                        font-family: system-ui, sans-serif;
                        background: #f4f6f9;
                        color: #1a1a2e;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        padding: 2rem;
                    }
                    .card {
                        background: #fff;
                        border-radius: 12px;
                        box-shadow: 0 4px 24px rgba(0,0,0,.08);
                        padding: 2.5rem 3rem;
                        max-width: 560px;
                        width: 100%;
                    }
                    h1 { font-size: 1.75rem; margin-bottom: .5rem; }
                    .badge {
                        display: inline-block;
                        background: #e0f2fe;
                        color: #0369a1;
                        font-size: .75rem;
                        font-weight: 600;
                        padding: .2rem .6rem;
                        border-radius: 99px;
                        margin-bottom: 1.5rem;
                    }
                    p { color: #555; line-height: 1.6; margin-bottom: 1.5rem; }
                    ul { list-style: none; display: flex; flex-direction: column; gap: .6rem; }
                    ul li a {
                        display: flex;
                        align-items: center;
                        gap: .5rem;
                        color: #0369a1;
                        text-decoration: none;
                        font-family: monospace;
                        font-size: .9rem;
                    }
                    ul li a:hover { text-decoration: underline; }
                    ul li a::before { content: "→"; font-family: sans-serif; }
                </style>
            </head>
            <body>
                <div class="card">
                    <h1>Custom OIDC Provider</h1>
                    <span class="badge">OpenID Connect 1.0 · RFC 6749</span>
                    <p>This is a lightweight, standards-compliant OpenID Connect identity provider. Use the endpoints below to integrate.</p>
                    <ul>
                        <li><a href="{{issuer}}/.well-known/openid-configuration">/.well-known/openid-configuration</a></li>
                        <li><a href="{{issuer}}/.well-known/jwks.json">/.well-known/jwks.json</a></li>
                        <li><a href="{{issuer}}/connect/authorize">/connect/authorize</a></li>
                        <li><a href="{{issuer}}/connect/token">/connect/token</a></li>
                        <li><a href="{{issuer}}/connect/userinfo">/connect/userinfo</a></li>
                    </ul>
                </div>
            </body>
            </html>
            """, "text/html; charset=utf-8"));

        return app;
    }
}
