-- SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
--
-- SPDX-License-Identifier: MIT

vim.filetype.add({ extension = { proto = "proto" } })

vim.api.nvim_create_autocmd("FileType", {
  pattern = "proto",
  callback = function(args)
    vim.bo[args.buf].commentstring = "// %s"
    vim.cmd([[
      syntax match protoComment "//.*$"
      syntax region protoComment start="/\*" end="\*/"
      syntax region protoString start=+"+ end=+"+
      syntax keyword protoKeyword syntax package import option message enum
            \ service rpc returns repeated optional required reserved oneof
            \ map extend extensions group stream
      highlight default link protoComment Comment
      highlight default link protoString String
      highlight default link protoKeyword Keyword
    ]])

    local root = vim.fs.root(args.buf, { "buf.yaml", "buf.work.yaml", ".git" })
        or vim.env.PROTOTEXT_PROTO_ROOT

    vim.lsp.start({
      name = "buf",
      cmd = { "buf", "lsp", "serve" },
      root_dir = root,
    })
  end,
})

vim.api.nvim_create_autocmd("LspAttach", {
  callback = function(args)
    local opts = { buffer = args.buf, silent = true }
    vim.keymap.set("n", "gd", vim.lsp.buf.definition, opts)
    vim.keymap.set("n", "gr", vim.lsp.buf.references, opts)
    vim.keymap.set("n", "K", vim.lsp.buf.hover, opts)
  end,
})
