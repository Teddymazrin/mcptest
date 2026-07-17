# Azure Lighthouse Notes

Azure Lighthouse lets a service provider manage resources in a customer's
Azure tenant without switching directories. Access is granted through a
delegation defined in an ARM template, specifying which Azure AD groups or
users from the provider tenant get which roles in the customer subscription.

Key points:
- Delegations are scoped to a subscription or resource group, not the whole tenant.
- Built-in roles like Contributor or Reader can be delegated; Owner cannot.
- Customers can revoke a delegation at any time from their own tenant.
- Lighthouse is what makes cross-tenant CSP support possible without guest accounts.
