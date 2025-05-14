package templates

import (
	_ "embed"
	"html/template"
	"time"
)

type SignupEmailData struct {
	Code template.HTML
	Link template.URL
}

//go:embed signup_email.html
var SignupEmailTemplate string

// <mjml>
//   <mj-body>
//     <mj-section>
//       <mj-column>
//         <mj-text align="center" font-size="22px" color="#424242" font-family="helvetica" font-weight="700">Your Markdown Ninja Registration Code</mj-text>
//         <mj-divider border-color="#dddddd" border-width="2px"></mj-divider>
//         <mj-text font-size="20px" color="#424242" font-family="helvetica" align="center" padding-top="30px">{{ .Code }}</mj-text>

//         <mj-text font-size="15px" padding-top="40px">or click the following URL: <a href="{{ .Link }}">{{ .Link }}</a></mj-text>
//       </mj-column>
//     </mj-section>
//   </mj-body>
// </mjml>

//go:embed login_alert_email.html
var LoginAlertEmailTemplate string

type LoginAlertEmailData struct {
	Name string
	Time time.Time
	// CountryName string
	// IP   string
}

// <mjml>
//   <mj-body>
//     <mj-section>
//       <mj-column>
//         <mj-text align="center" font-size="22px" color="#424242" font-family="helvetica" font-weight="700">Login Notification</mj-text>
//         <mj-divider border-color="#dddddd" border-width="2px"></mj-divider>
//         <mj-text font-size="19px" color="#424242" font-family="helvetica" align="left" padding-top="30px">
//           Hello {{ .Name }}, <br/><br/>
// A new device connected to your Markdown Ninja account on {{ .Time }}<br/><br/>
// If it's not you, please immediately <a href="https://markdown.ninja/contact">contact support</a> to see how we can help secure your account, otherwise you can safely ignore this email.
//        </mj-text>
//       </mj-column>
//     </mj-section>
//   </mj-body>
// </mjml>

//go:embed two_fa_disabled_email.html
var TwoFaDisabledEmailTemplate string

type TwoFaDisabledEmailData struct {
	Name string
}

// <mjml>
//   <mj-body>
//     <mj-section>
//       <mj-column>
//         <mj-text align="center" font-size="22px" color="#424242" font-family="helvetica" font-weight="700">2FA Disabled</mj-text>
//         <mj-divider border-color="#dddddd" border-width="2px"></mj-divider>
//         <mj-text font-size="19px" color="#424242" font-family="helvetica" align="left" padding-top="30px">2FA has been disabled for your Markdown Ninja account. Please <a href="https://markdown.ninja/contact">contact support</a> if it's not you. <br /></mj-text>
//       </mj-column>
//     </mj-section>
//   </mj-body>
// </mjml>
