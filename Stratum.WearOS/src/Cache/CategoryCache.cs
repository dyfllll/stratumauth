// Copyright (C) 2025 jmh
// SPDX-License-Identifier: GPL-3.0-only

using Android.Content;
using Stratum.Droid.Shared.Wear;

namespace Stratum.WearOS.Cache
{
    public class CategoryCache(Context context) : ListCache<WearCategory>("categories", context);
}