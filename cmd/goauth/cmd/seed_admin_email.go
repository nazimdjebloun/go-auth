package cmd

// The seed-admin email lives here, apart from the seeding logic, and
// deliberately does not go through port.TemplateProvider like the library's
// emails do. It is sent by a compiled CLI, which has no way to accept a Go
// interface from an operator, so routing it through the swappable path would
// buy nothing and would put a CLI-only message in the library's template set.
//
// It is also fully static: no app name, no links, no interpolation. There is
// nothing here for an operator to configure and nothing for a URL validator to
// check, which is the whole reason it can stay a plain constant instead of a
// parsed template.

const adminAccountCreatedSubject = "Your admin account is ready"

const adminAccountCreatedHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your admin account is ready</title>
</head>
<body style="margin:0;padding:0;background-color:#f4f4f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f7;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background-color:#ffffff;border-radius:8px;overflow:hidden;">
          <tr>
            <td style="padding:40px 48px;">
              <h1 style="margin:0 0 24px;font-size:24px;font-weight:600;color:#1a1a1a;">Your admin account is ready</h1>
              <p style="margin:0 0 16px;font-size:16px;line-height:24px;color:#4a4a4a;">
                An admin account was just created for you.
              </p>
              <p style="margin:0 0 16px;font-size:16px;line-height:24px;color:#4a4a4a;">
                You'll receive a two-factor code by email each time you log in, so this address needs to stay reachable.
              </p>
              <p style="margin:0;font-size:14px;line-height:20px;color:#999999;">
                Receiving this email is what confirms the code delivery works.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
`

const adminAccountCreatedText = `Your admin account is ready

An admin account was just created for you.

You'll receive a two-factor code by email each time you log in, so this address needs to stay reachable.

Receiving this email is what confirms the code delivery works.
`

// adminAccountCreatedEmail returns the subject, HTML body and text body sent to
// prove the mailer works before the admin row is written.
func adminAccountCreatedEmail() (subject, html, text string) {
	return adminAccountCreatedSubject, adminAccountCreatedHTML, adminAccountCreatedText
}
