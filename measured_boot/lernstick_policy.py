import typing
import re

from . import policies
from . import tests
from .policies import RefState


# Relative simple UEFI event log policy based on the Example policy provided by Keylime
# Copy into keylime.elchecking


class LernstickPolicy(policies.Policy):
    relevant_pcrs = frozenset(list(range(10)) + [14])

    # Regex that should cover all the valid kernel commandline options in our configuration

    # Valid locales currently supported by the Lernstick
    locales = [r"de_CH\.UTF-8", r"de_AT\.UTF-8", r"de_DE\.UTF-8", r"fr_CH\.UTF-8", r"it_CH\.UTF-8", r"en_US\.UTF-8",
               r"es_AR\.UTF-8", r"es_ES\.UTF-8", r"pt_BR\.UTF-8", r"sq_AL\.UTF-8", r"ku_TR\.UTF-8", r"ru_RU\.UTF-8",
               r"fa_IR"]
    # Supported keyboard layout configurations
    keyboard_layouts = [r"ch,ch\(fr\),de,fr", r"ch\(fr\),ch,fr,de", r"de,ch,ch\(fr\),fr", r"it,ch,ch(fr),fr",
                        r"us,ch,ch\(fr\),de", r"es,us,ch,ch\(fr\)", r"br,pt,us,ch", r"ru,ch,de,us", r"al,us,ch,de"]
    # Supported desktops (only text or GNOME are used in the exam environment)
    desktops = ["gnome nottyautologin", "no"]
    # default live-boot configuration
    default_append = "boot=live nonetworking config persistence-encryption=luks,none lernstick_efi_boot noeject"
    # live-media settings
    live_media = ["", " live-media=removable live-media-timeout=10", " live-media=usb live-media-timeout=10"]
    # persistence setup
    persistence_media = ["", " persistence-media=removable"]
    persistence = ["", " persistence", " persistence persistence-read-only"]
    # swap options
    swap = ["", " swapon"]
    quiet = ["", " quiet splash"]

    kernel_cmd_regex = f"/live/vmlinuz {default_append} locales=({'|'.join(locales)})" \
                       f" keyboard-layouts=({'|'.join(keyboard_layouts)}) desktop=({'|'.join(desktops)})" \
                       f"({'|'.join(live_media)})({'|'.join(persistence_media)})({'|'.join(persistence)})" \
                       f"({'|'.join(swap)})({'|'.join(quiet)}) custom_options"

    def get_relevant_pcrs(self) -> typing.FrozenSet[int]:
        return self.relevant_pcrs

    def refstate_to_test(self, refstate: RefState) -> tests.Test:
        # If emtpy refstate is supplied we default to accept all for testing
        if len(refstate.items()) == 0:
            return tests.AcceptAll()

        dispatcher = tests.Dispatcher(('PCRIndex', 'EventType'))
        vd = tests.VariableDispatch()

        # This event does not have an impact and does not extend a PCR
        dispatcher.set((0, 'EV_NO_ACTION'), tests.AcceptAll())

        # Firmware specific numbers and binaries. We currently accept all,
        # but in the future can extract this information from the submitted event log.
        dispatcher.set((0, 'EV_S_CRTM_VERSION'), tests.AcceptAll())
        dispatcher.set((0, 'EV_EFI_PLATFORM_FIRMWARE_BLOB'), tests.AcceptAll())

        # Check if SecureBoot is enabled
        dispatcher.set((7, 'EV_EFI_VARIABLE_DRIVER_CONFIG'), vd)
        vd.set('8be4df61-93ca-11d2-aa0d-00e098032b8c', 'SecureBoot',
               tests.FieldTest('Enabled', tests.StringEqual('Yes')))

        # TODO only allow PKs and KEKs from known good vendors
        vd.set('8be4df61-93ca-11d2-aa0d-00e098032b8c', 'PK', tests.OnceTest(tests.AcceptAll()))
        vd.set('8be4df61-93ca-11d2-aa0d-00e098032b8c', 'KEK', tests.OnceTest(tests.AcceptAll()))
        vd.set('d719b2cb-3d3a-4596-a3bc-dad00e67656f', 'db', tests.OnceTest(tests.AcceptAll()))
        vd.set('d719b2cb-3d3a-4596-a3bc-dad00e67656f', 'dbx', tests.OnceTest(tests.AcceptAll()))
        vd.set("605dab50-e046-4300-abb6-3dd810dd8b23", "SbatLevel", tests.OnceTest(tests.AcceptAll()))
        vd.set("605dab50-e046-4300-abb6-3dd810dd8b23", "Shim", tests.OnceTest(tests.AcceptAll()))
        vd.set(
            "605dab50-e046-4300-abb6-3dd810dd8b23",
            "MokListTrusted",
            tests.OnceTest(
                tests.Or(
                    tests.FieldTest("Enabled", tests.StringEqual("Yes")),
                    tests.FieldTest("Enabled", tests.StringEqual("No")),
                )
            ),
        )

        # Test for validating the applications that are loaded in UEFI
        tt = [tests.DigestTest(refstate["boot"]["bootx64.efi"]),
              tests.DigestTest(refstate["boot"]["grubx64.efi"]),
              tests.DigestTest(refstate["boot"]["vmlinuz"])]
        # Some Grub versions load the vmlinuz image twice
        tt2 = [tests.DigestTest(refstate["boot"]["bootx64.efi"]),
              tests.DigestTest(refstate["boot"]["grubx64.efi"]),
              tests.DigestTest(refstate["boot"]["vmlinuz"]),
              tests.DigestTest(refstate["boot"]["vmlinuz"])]

        bsa_test = tests.Or(tests.TupleTest(*tt), tests.TupleTest(*tt2))

        events_final = tests.DelayToFields(
            tests.FieldsTest(
                bsas=bsa_test,

            ),
            'bsas')

        # A list of allowed digests for firmware from device driver appears
        # in PCR2, event type EV_EFI_BOOT_SERVICES_DRIVER. Here we will just
        # accept everything
        dispatcher.set((2, 'EV_EFI_BOOT_SERVICES_DRIVER'),
                       tests.AcceptAll())

        # Accept all boot order entries
        dispatcher.set((1, 'EV_EFI_VARIABLE_BOOT'), tests.VariableTest(
            '8be4df61-93ca-11d2-aa0d-00e098032b8c',
            re.compile('BootOrder|Boot[0-9a-fA-F]+'),
            tests.AcceptAll()))

        # EV_EFI_ACTION and EV_SEPARATOR do not any meaningful information
        dispatcher.set((4, 'EV_EFI_ACTION'), tests.AcceptAll())
        for pcr in range(8):
            dispatcher.set((pcr, 'EV_SEPARATOR'), tests.AcceptAll())

        # Ignore all GPT related events
        dispatcher.set((5, 'EV_EFI_GPT_EVENT'), tests.AcceptAll())

        # Ignore shim CA and sbat entries. We already checked if it is the correct binary
        dispatcher.set((7, 'EV_EFI_VARIABLE_AUTHORITY'), tests.AcceptAll())

        # Validate that only the correct shim, grub and kernel was used
        dispatcher.set((4, 'EV_EFI_BOOT_SERVICES_APPLICATION'),
                       events_final.get('bsas'))

        # Ignore Mok DB entries generated by the shim
        dispatcher.set((14, 'EV_IPL'), tests.AcceptAll())

        # Verify files loaded by Grub
        grub_tests = []
        for name, digest in refstate["grub_files"].items():
            test = tests.And(
                tests.DigestTest(digest),
                tests.FieldTest('Event', tests.FieldTest('String', tests.RegExp(f".*{name}")))
            )
            grub_tests.append(test)

        # Check if the measured vmlinuz and initrd from Grub matches our expected values
        vmlinuz = tests.And(
            tests.DigestTest(refstate["kernel"]["vmlinuz"]),
            tests.FieldTest('Event', tests.FieldTest('String', tests.RegExp(f"/live/vmlinuz")))
        )
        initrd = tests.And(
            tests.DigestTest(refstate["kernel"]["initrd"]),
            tests.FieldTest('Event', tests.FieldTest('String', tests.RegExp(f"/live/initrd.img")))
        )

        # Ignore grub.cfg hash for now because we want to persist language and keyboard settings
        # In the future we ship a list with all possible hashes
        grub_cfg = tests.FieldTest('Event', tests.FieldTest('String', tests.RegExp("/boot/grub/grub.cfg")))

        dispatcher.set((9, 'EV_IPL'), tests.Or(*grub_tests, grub_cfg, vmlinuz, initrd))

        # Allow all Grub commands to be run and validate the kernel command line
        dispatcher.set((8, 'EV_IPL'), tests.FieldTest('Event', tests.FieldTest('String', tests.Or(
            tests.RegExp('grub_cmd: .*', re.DOTALL),
            tests.And(
                tests.RegExp(f'kernel_cmdline: {self.kernel_cmd_regex}'))
        ))))

        dispatcher.set((5, 'EV_EFI_ACTION'), tests.AcceptAll())

        events_test = tests.FieldTest('events',
                                      tests.And(
                                          events_final.get_initializer(),
                                          tests.IterateTest(
                                              dispatcher, show_elt=True),
                                          events_final),
                                      show_name=False)

        # Check for CRTM using PCR0 value in strict mode
        crtm_test = tests.AcceptAll()
        if refstate.get("crtm"):
            crtm_test = tests.FieldTest('pcrs',
                                        tests.FieldTest('sha256',
                                                        tests.FieldTest('0',
                                                                        tests.IntEqual(int(refstate["crtm"], 0)))))
        return tests.And(events_test, crtm_test)


policies.register('lernstick', LernstickPolicy())
