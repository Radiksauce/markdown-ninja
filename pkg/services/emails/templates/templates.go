package templates

import (
	_ "embed"
	"html/template"
)

//go:embed newsletter_email.html
var NewsletterEmailTemplate string

type NewsletterEmailData struct {
	Subject         string
	Content         template.HTML
	UnsubscribeLink template.URL
}

// <mjml>
//   <mj-head>
//     <mj-style>
//       hr {
//       	opacity: 0.2;
//       }
//       h1 {
//       	font-size: 30px;
//      	}
//       h2 {
//       	font-size: 24px;
//      	}
//       h3 {
//       	font-size: 22px;
//      	}
//       h4 {
//       	font-size: 20px;
//      	}
//       p, h5 {
//       	font-size: 18px;
//      	}
//       code {
//         font-size: 15px;
//       }
//       :not(pre) > code {
//         background-color: #e9e9e9;
//         padding: 1px;
//         border-radius: 2px;
//       }
//       p, pre, img, h1, h2, h3, h4, h5 {
//         margin-top: 20px;
//       	margin-bottom: 20px;
//       }
//       pre {
//       	padding: 8px;
//       	border-radius: 4px;
//       	overflow-x: scroll;
//       	display: block;
//       }
//       img {
//         max-width: 100%;
//         height: auto;
//         border-radius: 6px;
//         display: block;
//         margin-left: auto;
//         margin-right: auto;
//         margin-top: 10px;
//         margin-bottom: 10px;
//       }
//     </mj-style>
//   </mj-head>
//   <mj-body>
//     <mj-section>
//       <mj-column>
//         <mj-text align="center" font-size="30px" color="#424242" font-family="helvetica" font-weight="700">{{ .Subject }}</mj-text>
//         <mj-divider border-color="#dddddd" border-width="2px"></mj-divider>
//         <mj-text font-size="19px" color="#424242" font-family="helvetica">{{ .Content }}</mj-text>
//       </mj-column>
//     </mj-section>
//     <mj-section padding-top="30px">
//       <mj-column>
//       	<mj-divider border-color="#dddddd" border-width="1px"></mj-divider>
//         <mj-text align="center" font-size="12px" color="#424242" font-family="helvetica">
//           <a href="{{ .UnsubscribeLink }}">Unsubscribe</a>
//         </mj-text>
//       </mj-column>
//     </mj-section>
//   </mj-body>
// </mjml>
