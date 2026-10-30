export function guardInvoice(invoice, session) {
  return !!invoice && invoice.user_id === session.userId;
}
