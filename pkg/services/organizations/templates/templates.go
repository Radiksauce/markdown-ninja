package templates

import (
	_ "embed"
)

//go:embed staff_invitation_email.html
var StaffInvitationEmailTemplate string

type StaffInvitationEmailData struct {
	InviterEmail     string
	OrganizationName string
}

// <mjml>
//   <mj-body>
//     <mj-section>
//       <mj-column>
//         <mj-text align="center" font-size="22px" color="#424242" font-family="helvetica" font-weight="700">You have been invited to join an organization</mj-text>
//         <mj-divider border-color="#dddddd" border-width="2px"></mj-divider>
//         <mj-text font-size="18px" color="#424242" font-family="helvetica" padding-top="30px">Hello, <br /><br />
//           {{ .InviterEmail }} invited you to join the {{ .OrganizationName }} organization on <a href="https://markdown.ninja">Markdown Ninja</a>. <br /> <br />

//           You can see, accept and decline your invitations on your <a href="https://markdown.ninja/account">account page</a>. <br /> <br />

//           If you don't already have one, you can create a Markdown Ninja <a href="https://markdown.ninja">here</a>. <br /> <br />

//           Kind regards, <br />
//           The Markdown Ninja team

//           <br /><br />
//           If this invitation was not expected, you can ignore it.
//         </mj-text>
//       </mj-column>
//     </mj-section>
//   </mj-body>
// </mjml>
