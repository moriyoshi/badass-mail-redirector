package types

import "context"

type Outlet func(ctx context.Context, domain string, mails []Mail) error
