package templates

import (
	_ "embed"
	"html/template"
)

//go:embed verify_email_email.html
var VerifyEmailEmailTemplate string

type VerifyEmailEmailData struct {
	Link template.URL
}

// <mjml>
//   <mj-body>
//     <mj-section>
//       <mj-column>
//         <mj-text align="center" font-size="22px" color="#424242" font-family="helvetica" font-weight="700">Confirm Your Email</mj-text>
//         <mj-divider border-color="#dddddd" border-width="2px"></mj-divider>
//         <mj-text font-size="20px" color="#424242" font-family="helvetica" align="center" padding-top="30px">Please click the following link to confirm your new Email: <br />
//           <a href="{{ .Link }}">{{ .Link }}</a> </mj-text>
//       </mj-column>
//     </mj-section>
//   </mj-body>
// </mjml>
