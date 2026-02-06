jQuery(document).ready(function ($) {
    // Target the Group Name field (Django admin standard: id_name)
    var $input = $('#id_name');

    if ($input.length > 0) {
        // Transform the text input into a Select2 ajax
        // We need to create a select element to replace/augment the input, or use the input if Select2 supports creating tags from dynamic sources, 
        // but typically Select2 works best on <select>.
        // Strategy: Hide text input, show Select2. On change, update text input.

        // However, converting a text input to select2 directly is tricker. 
        // Better approach: Use Select2 on the input directly if supported(tags: true) or replace it.

        // Let's try replacing it with a select that has the current value as a predefined option.

        var currentVal = $input.val();
        var $select = $('<select class="select2-ad-group" style="width: 100%"></select>');

        if (currentVal) {
            var option = new Option(currentVal, currentVal, true, true);
            $select.append(option);
        }

        $input.hide().after($select);

        $select.select2({
            placeholder: 'Digite para buscar um grupo do AD...',
            minimumInputLength: 2,
            ajax: {
                url: '/admin/utils/ad-groups/',
                dataType: 'json',
                delay: 250,
                data: function (params) {
                    return {
                        term: params.term
                    };
                },
                processResults: function (data) {
                    return {
                        results: data.results.map(function (item) {
                            // Extract CN from DN for display/value if needed, or just use CN if provided separately.
                            // The backend returns text=DN. We might want to just grab the CN to populate the name.
                            // Let's assume the user wants the bare Group Name (CN) for the Django Group Name.
                            var cn = item.id.split(',')[0].replace('CN=', '');
                            return { id: cn, text: cn + ' (' + item.id + ')' };
                        })
                    };
                },
                cache: true
            }
        });

        // Sync selected value back to the real input
        $select.on('select2:select', function (e) {
            var data = e.params.data;
            $input.val(data.id);
        });
    }
});
