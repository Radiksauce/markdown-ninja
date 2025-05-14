package templates

import (
	_ "embed"
	"html/template"
)

type LoginEmailData struct {
	Code template.HTML
	Link template.URL
}

//go:embed login_email.html
var LoginEmailTemplate string

// <mjml>
//   <mj-body>
//     <mj-section>
//       <mj-column>
//         <mj-text align="center" font-size="22px" color="#424242" font-family="helvetica" font-weight="700">Your Login Code</mj-text>
//         <mj-divider border-color="#dddddd" border-width="2px"></mj-divider>
//         <mj-text font-size="20px" color="#424242" font-family="helvetica" align="center" padding-top="30px">{{ .Code }}</mj-text>
//         <mj-text font-size="15px" padding-top="40px">or click the following URL: <a href="{{ .Link }}">{{ .Link }}</a></mj-text>
//       </mj-column>
//     </mj-section>
//   </mj-body>
// </mjml>

type SubscribeEmailData struct {
	Code template.HTML
	Link template.URL
}

//go:embed subscribe_email.html
var SubscribeEmailTemplate string

// <mjml>
//   <mj-body>
//     <mj-section>
//       <mj-column>
//         <mj-text align="center" font-size="22px" color="#424242" font-family="helvetica" font-weight="700">Your Confirmation Code</mj-text>
//         <mj-divider border-color="#dddddd" border-width="2px"></mj-divider>
//         <mj-text font-size="20px" color="#424242" font-family="helvetica" align="center" padding-top="30px">{{ .Code }}</mj-text>
//         <mj-text font-size="15px" padding-top="40px">or click the following URL: <a href="{{ .Link }}">{{ .Link }}</a></mj-text>
//       </mj-column>
//     </mj-section>
//   </mj-body>
// </mjml>
