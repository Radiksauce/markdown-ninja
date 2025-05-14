package notifications

import (
	_ "embed"
	"html/template"
)

type OrderConfirmationEmailData struct {
	AccountURL template.URL
	OrderID    string
}

//go:embed order_confirmation.html
var OrderConfirmationEmailTemplate string

// <mjml>
//   <mj-body>
//     <mj-section>
//       <mj-column>
//         <mj-text align="center" font-size="22px" color="#424242" font-family="helvetica" font-weight="700">Order #{{ .OrderID }} confirmed</mj-text>
//         <mj-divider border-color="#dddddd" border-width="2px"></mj-divider>
//         <mj-text font-size="20px" color="#424242" font-family="helvetica" align="center" padding-top="30px">Thank you for your order! You can now access your products, receipt and invoice in your account: <br />
//           <a href="{{ .AccountURL }}">{{ .AccountURL }}</a> </mj-text>
//       </mj-column>
//     </mj-section>
//   </mj-body>
// </mjml>
